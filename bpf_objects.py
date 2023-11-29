''' Pure python implementation of the pcap language parser.
Compiler backends.
'''


#
# Copyright (c) 2023 Red Hat, Inc., Anton Ivanov <anivanov@redhat.com>
# Copyright (c) 2023 Cambridge Greys Ltd <anton.ivanov@cambridgegreys.com>
#

import re
import json
from header_constants import ETHER, IP, ETH_PROTOS, IP_PROTOS
from code_objects import AbstractCode, AbstractProgram


IPV4_REGEXP = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")


def ipv4_to_word(ipv4):
    '''Simplistic convertor from ipv4 text form to 32 bit uint'''
    match = IPV4_REGEXP.match(ipv4)
    if match is not None:
        scale = 24
        total = 0
        for index in range(1,5):
            nibble = int(match.group(index))
            if nibble > 256 or nibble < 0:
                raise TypeError("Invalid IP address")
            total += nibble << scale
            scale -= 8
        return total
    raise TypeError("Invalid IP address")

# BPF instruction formats

FORMATS = [
    "x/%x",                   # 0  register x
    "[0x{:04X}]",             # 1  offset k in the packet
    "[x + 0x{:04X}]",         # 2  offset k + x in the packet
    "M[0x{:04X}]",            # 3  offset k in M
    "#0x{:04X}",              # 4  k literal
    "4*([0x{:04X}]&0xf)",     # 5  Lower nibble * 4 at byte offset k in the packet ???
    "0x{:04X}",               # 6  Label
    "#0x{:04X} jt {} jf {} ", # 7  #k, jt, jf
    "x/%x jt {} jf {}",       # 8  x, jt, jf
    "#0x{:04X} jt {}",        # 9  #k, jt
    "x/%x jt {}",             # 10 x, jt
    "a/%a",                   # 11 accumulator
    "0x{:04X}"                # 12 extensions
]

class CBPFCompilerState():
    '''CBPF Specific compiler state'''

    def __init__(self):
        self.regfile = []
        for index in range(0,16):
            self.regfile.append(True)
        self.offset = 0
        self.quals = []

    def next_free_reg(self):
        '''Next available reg in the scratch space'''
        for reg in self.regfile:
            if self.regfile[reg]:
                self.regfile[reg] = False
                return reg
        raise IndexError("No free scratch registers")

    def release(self, reg):
        '''Release stashed reg back for use'''
        self.regfile[reg] = True

    def add_qual(self, quals):
        '''Add qualifiers'''

        if not isinstance(quals, list):
            quals = [quals]

        for qual in quals:
            if not qual in self.quals:
                self.quals.append(qual)


SIZE_MODS = [None, "b", "h", None, ""]
NEXT_MATCH = "__next_match"
LAST_INSN = "__last_insn"
SUCCESS = "__success"
FAIL = "__fail"
PARENT_NEXT = "__parent_next"

class CBPFCode(AbstractCode):
    '''BPF variant of code generation'''
    def __init__(self, code="", reg="", size=4, mode=None, label=None):
        super().__init__(label=label)
        self.code = code + reg
        self.code += SIZE_MODS[size]
        self.mode = mode
        self.reg = reg
        self.size = size

    def __eq__(self, other):
        '''Equal - needed for tests'''
        return super().__eq__(other) and self.code == other.code and \
               self.values == other.values and self.mode == other.mode

    def __str__(self):
        '''Same as repr'''
        return self.__repr__()

    def __repr__(self):
        '''Printable form of BPF instructions'''
        res = ":\n".join(self.labels)

        res += "\t" + self.code


        if self.mode is not None:
            try:
                res += "\t" + FORMATS[self.mode].format(*self.values)
            except TypeError:
                res += f"cannot do {self.mode} {self.values}"
            except ValueError:
                res += f"incorrect argument format for {self.mode} {self.values}"
        return res

    def check_mode(self, mode, mask=None):
        '''Verify mode'''
        if not mode in mask:
            raise TypeError(f"Invalid Addressing mode {mode} not {mask} in ")

    def verbose_print(self):
        '''Print suitable for sticking the result into a test case'''

        name = self.__class__.__name__

        if self.reg != "":
            if len(self.labels) == 0:
                return f"code_objects.{name}({self.values},reg={self.reg}, size={self.size}, mode={self.mode})"
            return f"code_objects.{name}({self.values}, reg={self.reg}, size={self.size}, mode={self.mode}, label={self.labels})"
        if len(self.labels) == 0:
            return f"code_objects.{name}({self.values}, size={self.size}, mode={self.mode})"
        return f"code_objects.{name}({self.values}, size={self.size}, mode={self.mode}, label={self.labels})"

class LD(CBPFCode):
    '''Load into A or X'''
    def __init__(self, values, reg="", size=4, mode=None, label=None):
        if reg == "x":
            self.check_mode(mode, [3, 4, 5, 12])
        else:
            self.check_mode(mode, [1, 2, 3, 4, 12])
        super().__init__(code="ld", reg=reg, size=size, mode=mode, label=label)
        self.set_values(values)

class ST(CBPFCode):
    '''Store from A or X'''
    def __init__(self, values, reg="", size=4, mode=0, label=None):
        super().__init__(code="st", reg=reg, size=size, mode=mode, label=label)
        self.set_values(values)

class Jump(CBPFCode):
    '''Generic Jump.'''
    def __init__(self, code=None, values=None, mode=6, label=None, size=4):
        super().__init__(code=code, mode=mode, label=label)
        self.set_values(values)

    def resolve_refs(self, old_label, new_label):
        '''Update refs'''
        for index in range(0, len(self.values)):
            if self.values[index] == old_label:
                self.values[index] = new_label

class JMP(Jump):
    '''Unconditional Jump'''
    def __init__(self, values, label=None):
        super().__init__(code="jmp", mode=6, label=label)
        self.set_values(values)

class JA(Jump):
    '''Jump on Accumulator'''
    def __init__(self, values, label=None):
        super().__init__(code="ja", mode=6, label=label)
        self.set_values(values)

class CondJump(Jump):
    '''Conditional jumps'''
    def __init__(self, values, code="jeq", mode=None, label=None, size=4):
        if code in ["jeq", "jgt", "jge", "jset"]:
            self.check_mode(mode, [7, 8, 9, 10])
        else:
            self.check_mode(mode, [9, 10])
        super().__init__(code=code, mode=mode, label=label, size=size)
        self.set_values(values)

class JEQ(CondJump):
    '''Jump on equal'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="jeq", mode=mode, label=label, size=size)

class JNEQ(CondJump):
    '''Jump on not equal'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="jneq", mode=mode, label=label, size=size)

class JNE(CondJump):
    '''Jump on not equal'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="jne", mode=mode, label=label, size=size)

class JLT(CondJump):
    '''Jump on less then'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="jlt", mode=mode, label=label, size=size)

class JLE(CondJump):
    '''Jump on less or equal'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="jlt", mode=mode, label=label, size=size)

class JGT(CondJump):
    '''Jump on greater'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="jgt", mode=mode, label=label, size=size)

class JGE(CondJump):
    '''Jump on greater or equal'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="jge", mode=mode, label=label, size=size)

class JSET(CondJump):
    '''Jump on a set bit'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="jset", mode=mode, label=label, size=size)

class Arithmetics(CBPFCode):
    '''Generic arithmetic instruction'''
    def __init__(self, values, code=None, mode=None, label=None, size=4):
        self.check_mode(mode, [0, 4])
        super().__init__(code=code, mode=mode, label=label, size=size)
        self.set_values(values)

class ADD(Arithmetics):
    '''ADD instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="add", mode=mode, label=label, size=size)

class SUB(Arithmetics):
    '''SUB instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="sub", mode=mode, label=label, size=size)

class MUL(Arithmetics):
    '''MUL instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="mul", mode=mode, label=label, size=size)

class DIV(Arithmetics):
    '''DIV instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="div", mode=mode, label=label, size=size)

class MOD(Arithmetics):
    '''MOD instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="mod", mode=mode, label=label, size=size)

class AND(Arithmetics):
    '''Arithmetic AND instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="and", mode=mode, label=label, size=size)

class OR(Arithmetics):
    '''Arithmetic OR instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="or", mode=mode, label=label, size=size)

class XOR(Arithmetics):
    '''Arithmetic XOR instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="xor", mode=mode, label=label, size=size)

class LSH(Arithmetics):
    '''LSH instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="lsh", mode=mode, label=label, size=size)

class RSH(Arithmetics):
    '''RSH instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="rsh", mode=mode, label=label, size=size)

class NEG(CBPFCode):
    '''NEG instruction'''
    def __init__(self, label=None, size=4):
        super().__init__(code="neg", label=label, size=size)

class TAX(CBPFCode):
    '''Transfer A to X'''
    def __init__(self, label=None, size=4):
        super().__init__(code="tax", label=label, size=size)

class TXA(CBPFCode):
    '''Transfer X to A'''
    def __init__(self, label=None, size=4):
        super().__init__(code="txa", label=label, size=size)

class RET(CBPFCode):
    '''RET with result.
       cBPF convention is 0 for failure and non
       negative packet "size" for success
    '''
    def __init__(self, values, mode=4, label=None, size=4):
        self.check_mode(mode, [4, 11])
        super().__init__(code="ret", mode=mode, label=label, size=size)
        self.set_values(values)


V4_NET_REGEXP = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})")

class CBPFProgram(AbstractProgram):
    '''cBPF variant of AbstractProgram'''
    def __init__(self, match_object=None, offset=0,
                on_success=NEXT_MATCH, on_failure=FAIL, frags=None, label=None, update_labels=False,
                attribs=None):

        super().__init__(frags=frags, label=label, attribs=attribs)
        self.code = []
        self.offset_code = []
        self.compiled_offsets = False
        self.use_offset = False
        self.ext_label = f"__ext__{self.loc}"
        if attribs is None:
            self.attribs.update({
                "on_success": on_success,
                "on_failure": on_failure,
                "name":"generic",
                "offset":offset,
            })

            if match_object is not None:
                self.attribs["match_object"] = match_object

            if update_labels:
                if on_success is not None:
                    self.set_on_success(on_success)
                if on_failure is not None:
                    self.set_on_failure(on_failure)
        else:
            self.attribs = attribs.copy()
            try:
                self.frags = attribs["frags"]
            except KeyError:
                pass

    def update_labels(self):
        '''Update code start/end labels'''
        if len(self.code) > 0:
            self.code[0].add_label(f"__start__{self.loc}")
            self.code[-1].add_label(f"__end__{self.loc}")

    def add_code(self, code):
        '''Add code and update jump label in last frag'''
        if len(self.frags) > 0:
            self.frags[-1].replace_value(NEXT_MATCH, self.ext_label)
        code[0].add_label(self.ext_label)
        self.code.extend(code)

    def add_offset_code(self, code):
        '''Add code and update jump label in last frag'''
        self.offset_code.extend(code)

    def compile(self, branch_state=None):
        '''Compile the code and mark it as compiled'''

        if branch_state is None:
            branch_state = CBPFCompilerState()

        super().compile(branch_state)

        try:
            branch_state.add_qual(f"{self.name}.{self.match_object}")
        except KeyError:
            pass

        for frag in self.frags:
            frag.update_labels()

        for index in range(0, len(self.frags) -1):
            self.frags[index].replace_value(
                NEXT_MATCH, self.frags[index + 1].get_start_label())


    def compile_offsets(self, branch_state=None):
        '''Compile the code and mark it as compiled'''
        if not self.compiled_offsets:
            try:
                # top level
                for frag in self.attribs["offset_frags"]:
                    frag.compile_offsets(branch_state)
            except KeyError:
                for frag in self.frags:
                    frag.compile_offsets(branch_state)
            self.compiled_offsets = True
        

    def set_on_success(self, on_success, last_frag=False):
        '''Set jump on true.'''
        self.attribs["on_success"] = on_success
        if last_frag:
            try:
                self.frags[-1].set_on_success(on_success, last_frag=last_frag)
            except IndexError:
                pass
        else:
            for frag in self.frags:
                frag.set_on_success(on_success)

    def set_on_failure(self, on_failure, last_frag=False):
        '''Set jump on false.'''
        self.attribs["on_failure"] = on_failure
        if last_frag:
            self.frags[-1].set_on_failure(on_failure, last_frag=last_frag)
        else:
            for frag in self.frags:
                frag.set_on_failure(on_failure)

    @property
    def offset(self):
        '''match_object getter'''
        return self.attribs["offset"]

    @property
    def match_object(self):
        '''match_object getter'''
        return self.attribs["match_object"]

    @property
    def on_success(self):
        '''on_success getter'''
        return self.attribs["on_success"]

    @property
    def on_failure(self):
        '''on_failure getter'''
        return self.attribs["on_failure"]

    def get_start_label(self):
        '''Set start label'''
        if len(self.frags) > 0:
            return self.frags[0].get_start_label()

        return f"__start__{self.loc}"

    def get_end_label(self):
        '''Get start label'''
        return self.frags[-1].get_end_label()

    def get_next_match(self, item):
        '''Get next match/code fragment'''
        if self.frags[-1] == item:
            return self.parent.get_next_match(self)
        return self.frags[self.frags.index(item) + 1].get_start_label()


    def get_offset_code(self):
        '''Get offset specific code'''
        code = []
        try:
            # top level
            for frag in self.attribs["offset_frags"]:
                code.extend(frag.get_offset_code())
        except KeyError:
            for frag in self.frags:
                code.extend(frag.get_offset_code())
        code.extend(self.offset_code)
        return code
        

    def resolve_refs(self):
        '''Second pass'''

        code = self.get_code()
        labels = {}

        for index in range(0, len(code)):
            for label in code[index].labels:
                labels[label] = index

        for index in range(0, len(code)):
            for key, value in labels.items():
                code[index].resolve_refs(key, value)

        for index in range(0, len(code)):
            for label in code[index].labels:
                code[index].labels = set()


# These are way too cBPF specific to try to make them into generic instances

class ProgSuccess(CBPFProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, attribs=None):
        super().__init__(attribs=attribs)
        self.attribs["name"] = "success"

    def compile(self, branch_state=None):
        super().compile(branch_state)
        self.add_code([RET(0xFFFF, label=[SUCCESS])])

class ProgFail(CBPFProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, attribs=None):
        super().__init__(attribs=attribs)
        self.attribs["name"] = "fail"

    def compile(self, branch_state=None):
        super().compile(branch_state)
        self.add_code([RET(0, label=[LAST_INSN, FAIL])])


class ProgL2(CBPFProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, match_object=None, offset=0, attribs=None):
        if attribs is not None:
            super().__init__(attribs=attribs)
        else:
            super().__init__(match_object=match_object, offset=offset)
            self.attribs["name"] = "l2"

    def compile(self, branch_state=None):

        super().compile(branch_state)
        branch_state.offset = ETHER["size"]

        if isinstance(self.match_object, str):
            self.add_code([
                LD(ETHER["proto"] + self.offset, size=2, mode=1),
                JEQ([ETH_PROTOS[self.match_object], self.on_success, self.on_failure], mode=7),
            ])
        else:
            self.add_code([
                LD(ETHER["proto"] + self.offset, size=2, mode=1),
                JEQ([self.match_object, self.on_success, self.on_failure], mode=7),
            ])

    def compile_offsets(self, branch_state=None):
        '''L2 offset'''
        super().compile_offsets(branch_state)

        return ETHER["size"]


class Prog8021Q(CBPFProgram):
    '''Vlan matcher'''
    def __init__(self, match_object, offset=0, attribs=None):
        if attribs is not None:
            super().__init__(attribs=attribs)
        else:
            super().__init__(frags=[ProgL2(match_object="qtag", offset=offset)], match_object=match_object, offset=offset)

    def compile(self, branch_state=None):

        super().compile(branch_state)

        branch_state.offset = ETHER["size"] + 4
        self.add_code([
            LD(self.offset + ETHER["size"] + 2, size=2, mode=1),
            AND(0x3F, mode=4),
            JEQ([self.match_object, self.on_success, self.on_failure], mode=7)
        ])

    def compile_offsets(self, branch_state=None):
        '''802.1q offset'''
        return super().compile_offsets(branch_state) + 4


class ProgL3(CBPFProgram):
    '''Layer 3 protocol matcher'''
    def __init__(self, match_object=None, offset=0, attribs=None):
        if attribs is not None:
            super().__init__(attribs=attribs)
        else:
            super().__init__(match_object=match_object, offset=offset)
            self.attribs["name"] = "l3"

    def compile(self, branch_state=None):
        '''Compile the code'''

        super().compile(branch_state)
        self.add_code([
            LD(self.offset + branch_state.offset + IP["proto"], size=1, mode=1),
            JEQ([self.match_object, self.on_success, self.on_failure], mode=7),
        ])

PORT = {
    "src": 0,
    "dst": 2
}

class ProgIP(CBPFProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, attribs=None, offset=0):
        super().__init__(frags=[ProgL2(match_object="ip", offset=offset)], attribs=attribs)
        self.attribs["name"] = "ip"

    def compile_offsets(self, branch_state=None):
        '''Compile offset past IP Headers'''
        super().compile_offsets(branch_state)
        print(branch_state.offset)
        self.add_offset_code([
            LD([branch_state.offset], size=1, mode=5, reg="x")
        ])

class ProgTCP(CBPFProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, attribs=None, offset=0):
        super().__init__(frags=[ProgIP(offset=offset), ProgL3(match_object=IP_PROTOS["tcp"], offset=offset)], attribs=attribs)
        self.attribs["name"] = "tcp"

    def compile_offsets(self, branch_state=None):
        '''Compile offset past IP Headers'''
        super().compile_offsets(branch_state)

        self.add_offset_code([
            LD([branch_state.offset + 12], size=1, mode=2),
            RSH([2], mode=4),
            ADD([], mode=0),
            TAX(),
        ])


class ProgPort(CBPFProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, match_object=None, frags=None, attribs=None, offset=0):

        if frags is None and attribs is None:
            frags = [ProgIP()]

        super().__init__(match_object=match_object, frags=frags, attribs=attribs)
        self.attribs["name"] = "port"

    def compile(self, branch_state=None):
        '''Compile the code'''

        super().compile(branch_state)

        code = [
            LD([branch_state.offset], size=1, mode=5, reg="x")
        ]

        if self.frags[0].result is None:
            self.stashed_in = branch_state.next_free_reg()
            self.add_code([ST([self.stashed_in], mode=3)])

        self.compile_offsets(branch_state)

        if "src" in self.quals:
            code.append(
                LD([branch_state.offset], size=2, mode=2),
            )
        if "dst" in self.quals:
            code.append(
                LD([branch_state.offset + 2], size=2, mode=2),
            )

        if self.frags[0].result is None:
            code.append(LD([self.stashed_in], reg="x", mode=3))
            code.append(JEQ([self.on_success, self.on_failure], mode=8))
            branch_state.release(self.stashed_in)
        else:
            code.append(JEQ([self.frags[0].result, self.on_success, self.on_failure], mode=7))
        self.add_code(code)

class ProgIPv4(CBPFProgram):
    '''Basic match on v4 address or network.
    '''
    def __init__(self, match_object=None, offset=0, attribs=None, add_ip_check=True):

        if attribs is not None:
            super().__init__(attribs=attribs)
        else:
            super().__init__(match_object=match_object, offset=offset)
            if add_ip_check:
                self.frags = [ProgIP(offset=offset)]
        self.attribs["name"] = "ipv4"

    def add_quals(self, quals):
        '''Override add_quals to take care of "interesting" syntax'''
        super().add_quals(quals)
        if "srcordst" in self.quals or "srcanddst" in self.quals:
            left = ProgIPv4(match_object=self.match_object, offset=self.offset, add_ip_check=False)
            right = ProgIPv4(match_object=self.match_object, offset=self.offset, add_ip_check=False)
            left.add_quals("src")
            right.add_quals("dst")
            if "srcordst" in self.quals:
                self.frags.append(ProgOR(left=left, right=right))
            else:
                self.frags.append(ProgAND(left=left, right=right))

    def compile(self, branch_state=None):
        '''Generate the actual code for the match'''

        addr = V4_NET_REGEXP.match(self.match_object)
        location = None

        super().compile(branch_state)

        if "srcordst" in self.quals or "srcanddst" in self.quals:
            return

        for qual in self.quals:
            # Use only simple qualifiers. Skip protos, vlans, etc 
            if isinstance(qual, str):
                try:
                    location = branch_state.offset + self.offset + IP[qual]
                except KeyError:
                    pass
                if location is not None:
                    break
        if location is None:
            raise ValueError(f"Invalid address type specifier {self.quals}")


        code = [LD(location, size=4, mode=1)]
        if addr is not None:
            netmask = 0xffffffff ^ (0xffffffff >> int(addr.group(2)))
            code.extend([AND(netmask, mode=4), JEQ([ipv4_to_word(addr.group(1)), self.on_success, self.on_failure], mode=7)])
        else:
            code.append(JEQ([ipv4_to_word(self.match_object), self.on_success, self.on_failure], mode=7))
        self.add_code(code)


class ProgNOT(CBPFProgram):
    '''Negate the result of all frags.
    '''
    def __init__(self, frags=None, attribs=None):
        # swap on_success and on_failure

        super().__init__(frags=frags, attribs=attribs)
        self.attribs["name"] = "not"

    def compile(self, branch_state=None):
        '''Compile NOT - inverse true and false'''
        super().compile(branch_state)
        self.replace_value(NEXT_MATCH, "__temp_not")
        self.replace_value(FAIL, NEXT_MATCH)
        self.replace_value("__temp_not", FAIL)


class ProgOR(CBPFProgram):
    '''Perform logical OR on left and right frag(s)
    '''
    def __init__(self, left=None, right=None, attribs=None):
        if attribs is None:
            self.right = CBPFProgram(frags=right)
            self.left = CBPFProgram(frags=left)
            super().__init__(frags=[self.left, self.right])
        else:
            super().__init__(attribs=attribs)
            self.left=attribs["frags"][0]
            self.right=attribs["frags"][1]
        self.attribs["name"] = "or"

    def compile(self, branch_state=None):
        '''Compile OR - inverse true and false'''

        old_state = branch_state.quals.copy()
        offset = branch_state.offset
        self.left.compile(branch_state)
        branch_state.quals = old_state
        branch_state.offset = offset
        self.right.compile(branch_state)

        self.frags[0].replace_value(self.frags[1].get_start_label(), NEXT_MATCH)
        self.frags[0].replace_value(FAIL, self.frags[1].get_start_label())


class ProgAND(CBPFProgram):
    '''Perform logical AND on left and right frag(s)
    '''
    def __init__(self, left=None, right=None, attribs=None):
        if attribs is None:
            self.right = CBPFProgram(frags=right)
            self.left = CBPFProgram(frags=left)
            super().__init__(frags=[self.left, self.right])
        else:
            super().__init__(attribs=attribs)
            self.left=attribs["frags"][0]
            self.right=attribs["frags"][1]

        self.attribs["name"] = "and"

COMP_TABLE = {
    "<" : JLT,
    ">" : JGT,
    "==" : JEQ,
    "!=" : JNEQ,
    ">=" : JGE,
    "<=" : JLE
}

class ProgOffset(CBPFProgram):
    '''Perform computation of offset to payload
    '''
    def __init__(self, frags=None, attribs=None):
        super().__init__(frags=frags, attribs=attribs)
        self.attribs["name"] = "compute_offset"
        self.attribs["offset_frags"] = frags
        self.attribs["frags"] = []


    def compile(self, branch_state=None):
        '''We compile offset code instead of the normal
           match logic.
        '''

        super().compile(branch_state)
        super().compile_offsets(branch_state)

        code = self.get_offset_code()
        if len(code) == 0:
            # our relocation mechanism breaks if a prog does not
            # generate any code and has labels
            code.append(ADD([0], mode=4))


        # NOP - to ensure labels are computed correctly
        self.add_code(code)


COMP_TABLE = {
    "<" : JLT,
    ">" : JGT,
    "==" : JEQ,
    "!=" : JNEQ,
    ">=" : JGE,
    "<=" : JLE
}


class ProgLoad(CBPFProgram):
    '''Load a value from packet address
    '''
    def __init__(self, loc=0, size=4, attribs=None):
        if attribs is None:
            super().__init__()
            self.attribs["loc"] = loc
            self.attribs["size"] = size
        else:
            super().__init__(attribs=attribs)
        self.attribs["name"] = "ar_load"

    def compile(self, branch_state=None):
        '''Compile arithmetics'''

        super().compile(branch_state)

        super().compile_offsets(branch_state)

        if isinstance(self.attribs["loc"], Immediate):
            if self.use_offset:
               self.add_code([LD([self.attribs["loc"].attribs["match_object"] + branch_state.offset], size=self.attribs["size"], mode=2)])
            else:
               self.add_code([LD([self.attribs["loc"].attribs["match_object"] + branch_state.offset], size=self.attribs["size"], mode=1)])

class ProgIndexLoad(CBPFProgram):
    '''Perform arithmetic operations.
    '''
    def __init__(self, frags=None, size=4, attribs=None):
        if attribs is None:
            super().__init__(frags=frags)
            self.attribs["size"] = size
        else:
            super().__init__(attribs=attribs)
        self.attribs["name"] = "ar_load"

    def compile(self, branch_state=None):
        '''Compile arithmetics'''
        super().compile(branch_state)
        self.add_code([
            TAX(),
            LD([0], size=self.attribs["size"], mode=2)
        ])


COMPUTE_TABLE = {
    "+" : lambda x, y: x + y,
    "-" : lambda x, y: x - y,
    "*" : lambda x, y: x * y,
    "/" : lambda x, y: x / y,
    "%" : lambda x, y: x % y,
    "&" : lambda x, y: x & y,
    "|" : lambda x, y: x | y,
    "^" : lambda x, y: x ^ y,
    "<<" : lambda x, y: x << y, 
    ">>" : lambda x, y: x >> y,
    "<" : lambda x, y: x < y,
    ">" : lambda x, y: x > y,
    "==" : lambda x, y: x == y,
    "!=" : lambda x, y: not x == y,
    ">=" : lambda x, y: x >= y,
    "<=" : lambda x, y: x <= y
}


def compute(left, op, right):
    '''Dumb calculcator'''
    return COMPUTE_TABLE[op](left, right)


class ProgComp(CBPFProgram):
    '''Perform arithmetic comparisons.
    '''
    def __init__(self, op=None, left=None, right=None, attribs=None):
        self.using_stash = False
        if attribs is None:
            if isinstance(left, Immediate) or isinstance(right, Immediate):
                self.left = left
            else:
                self.left = StashResult(frags=left)
                self.using_stash = True
            self.right = right
            super().__init__(frags=[self.left, self.right])
            self.attribs["op"] = op
        else:
            super().__init__(attribs=attribs)
            self.left=attribs["frags"][0]
            self.right=attribs["frags"][1]
        self.attribs["name"] = "ar_comp"

    def compile(self, branch_state=None):
        '''Compile arithmetics'''
        super().compile(branch_state)

        if self.left.result is None and self.right.result is None:
            self.add_code([COMP_TABLE[self.attribs["op"]]([self.left.stashed_in, self.on_success, self.on_failure], mode=3)])

        if self.left.result is not None and self.right.result is None:
            self.add_code([COMP_TABLE[self.attribs["op"]]([self.left.result, self.on_success, self.on_failure], mode=7)])

        if self.left.result is None and self.right.result is not None:
            if isinstance(self.left, StashResult):
                self.left.code.pop()
            self.add_code([COMP_TABLE[self.attribs["op"]]([self.right.result, self.on_success, self.on_failure], mode=7)])

        if self.left.result is not None and self.right.result is not None:
            self.result = compute(self.left.result, self.attribs["op"], self.right.result)
            if self.result:
                self.add_code(JMP([self.on_success]))
            else:
                self.add_code(JMP([self.on_failure]))

        if self.using_stash:
            branch_state.release(self.left.stashed_in)

class Immediate(CBPFProgram):
    '''Fake leafe for immediate ops
    '''
    def __init__(self, match_object=None, attribs=None):
        if attribs is None:
            super().__init__(match_object=match_object)
        else:
            super().__init__(attribs=attribs)
        self.attribs["name"] = "immediate"

    def compile(self, branch_state=None):
        self.result = self.match_object


ARITH_TABLE = {
    "+" : ADD,
    "-" : SUB,
    "*" : MUL,
    "/" : DIV,
    "%" : MOD,
    "&" : AND,
    "|" : OR,
    "^" : XOR,
    "<<" : LSH,
    ">>" : RSH
}

class ProgArOp(CBPFProgram):
    '''Perform arithmetic operations.
    '''
    def __init__(self, op=None, left=None, right=None, attribs=None):
        self.using_stash = False
        if attribs is None:
            if isinstance(left, Immediate) or isinstance(right, Immediate):
                self.left = left
            else:
                self.left = StashResult(frags=left)
                self.using_stash = True
            self.right = right
            super().__init__(frags=[self.left, self.right])
            self.attribs["op"] = op
        else:
            super().__init__(attribs=attribs)
            self.left=attribs["frags"][0]
            self.right=attribs["frags"][1]

        self.attribs["name"] = "ar_op"

    def compile(self, branch_state=None):
        '''Compile arithmetics'''
        super().compile(branch_state)

        if self.left.result is None and self.right.result is None:
            self.add_code([
                    LD([self.left.stashed_in], reg="x", mode=3),
                    ARITH_TABLE[self.attribs["op"]](mode=0)
                ])

        if self.left.result is not None and self.right.result is None:
            self.add_code([ARITH_TABLE[self.attribs["op"]]([self.left.result], mode=4)])

        if self.left.result is None and self.right.result is not None:
            if isinstance(self.left, StashResult):
                self.left.code.pop()
            self.add_code([ARITH_TABLE[self.attribs["op"]]([self.right.result], mode=4)])

        if self.left.result is not None and self.right.result is not None:
            self.result = compute(self.left.result, self.attribs["op"], self.right.result)

        if self.using_stash:
            branch_state.release(self.left.stashed_in)

class ProgTAX(CBPFProgram):
    '''Perform arithmetic operations.
    '''
    def __init__(self, frags=None, attribs=None):
        if attribs is None:
            super().__init__(frags=frags)
        else:
            super().__init__(attribs=attribs)
        self.attribs["name"] = "tax"

    def compile(self, branch_state=None):
        '''Compile arithmetics'''
        super().compile(branch_state)
        self.add_code([TAX()])

class StashResult(CBPFProgram):
    '''Perform arithmetic operations.
    '''
    def __init__(self, frags=None, attribs=None):
        if attribs is None:
            super().__init__(frags=frags)
        else:
            super().__init__(attribs=attribs)
        self.attribs["name"] = "stash"
        self.stashed_in = None

    def compile(self, branch_state=None):
        '''Stash result in the first available scratch reg'''
        super().compile(branch_state)
        self.stashed_in = branch_state.next_free_reg()
        self.add_code([ST([self.stashed_in], mode=3)])


class ProgramEncoder(json.JSONEncoder):
    '''Serializer to JSON'''

    def default(self, o):
        if isinstance(o, CBPFProgram):
            return o.attribs.copy()
        return json.JSONEncoder.default(self, o)

def loads_hook(obj):
    '''Custom JSON deserializer'''
    try:
        return JUMPTABLE[obj["name"]](attribs=obj)
    except KeyError:
        return None


def finalize(prog):
    '''Add success and failure return instructions to the end'''
    return CBPFProgram(frags=[prog, ProgSuccess(), ProgFail()])

JUMPTABLE = {
    "generic":CBPFProgram,
    "ip":ProgIP,
    "l2":ProgL2,
    "l3":ProgL3,
    "tcp":ProgTCP,
#    "udp":ProgUDP,
    "port":ProgPort,
    "ipv4":ProgIPv4,
    "not":ProgNOT,
    "or":ProgOR,
    "and":ProgAND,
    "fail":ProgFail,
    "success":ProgSuccess,
    "ar_comp":ProgComp,
    "ar_op":ProgArOp,
    "ar_load":ProgLoad,
    "index_load":ProgIndexLoad,
    "immediate":Immediate,
    "stash":StashResult,
    "tax":ProgTAX,
    "compute_offset":ProgOffset
}
