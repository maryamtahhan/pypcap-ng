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
            res += "\t" + FORMATS[self.mode].format(*self.values)
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
        super().__init__(None, "neg", label=label, size=size)

class TAX(CBPFCode):
    '''Transfer A to X'''
    def __init__(self, label=None, size=4):
        super().__init__(None, "tax", label=label, size=size)

class TXA(CBPFCode):
    '''Transfer X to A'''
    def __init__(self, label=None, size=4):
        super().__init__(None, "txa", label=label, size=size)

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
        if len(self.code) > 0:
            self.code[0].add_label(f"__start__{self.loc}")
            self.code[-1].add_label(f"__end__{self.loc}")

    def add_code(self, code):
        '''Add code and update jump label in last frag'''
        if len(self.frags) > 0:
            self.frags[-1].replace_value(NEXT_MATCH, self.ext_label)
        code[0].add_label(self.ext_label)
        self.code.extend(code)


    def compile(self):
        '''Compile the code and mark it as compiled'''
        super().compile()

        for frag in self.frags:
            frag.update_labels()

        for index in range(0, len(self.frags) -1):
            self.frags[index].replace_value(
                NEXT_MATCH, self.frags[index + 1].get_start_label())


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

    def compile(self):
        super().compile()
        self.add_code([RET(0xFFFF, label=[SUCCESS])])

class ProgFail(CBPFProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, attribs=None):
        super().__init__(attribs=attribs)
        self.attribs["name"] = "fail"

    def compile(self):
        super().compile()
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

    def compile(self):


        super().compile()
        self.add_code([
            LD(ETHER["proto"] + self.offset, size=2, mode=1),
            JEQ([ETH_PROTOS[self.match_object], self.on_success, self.on_failure], mode=7),
        ])



class Prog8021Q(CBPFProgram):
    '''Vlan matcher'''
    def __init__(self, match_object, offset=0, attribs=None):
        if attribs is not None:
            super().__init__(attribs=attribs)
        else:
            super().__init__(frags=[ProgL2(match_object="qtag", offset=offset)], match_object=match_object, offset=offset)

    def compile(self):
        super().compile()
        self.add_code([
            LD(self.offset + ETHER["size"] + 2, size=2, mode=1),
            AND(0x3F, mode=4),
            JEQ([self.match_object, self.on_success, self.on_failure], mode=7)
        ])


class ProgL3(CBPFProgram):
    '''Layer 3 protocol matcher'''
    def __init__(self, match_object=None, offset=0, attribs=None):
        if attribs is not None:
            super().__init__(attribs=attribs)
        else:
            super().__init__(match_object=match_object, offset=offset)
            self.attribs["name"] = "l3"

    def compile(self):
        '''Compile the code'''
        super().compile()
        self.add_code([
            LD(self.offset + ETHER["size"] + IP["proto"], size=1, mode=1),
            JEQ([self.match_object, self.on_success, self.on_failure], mode=7),
        ])


class ProgIP(CBPFProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, attribs=None, offset=0):
        super().__init__(frags=[ProgL2("ip", offset=offset)], attribs=attribs)
        self.attribs["name"] = "ip"

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
            left.add_quals(set(["src"]))
            right.add_quals(set(["dst"]))
            if "srcordst" in self.quals:
                self.frags.append(ProgOR(left=left, right=right))
            else:
                self.frags.append(ProgAND(left=left, right=right))

    def compile(self):
        '''Generate the actual code for the match'''

        addr = V4_NET_REGEXP.match(self.match_object)
        location = None

        if "srcordst" in self.quals or "srcanddst" in self.quals:
            super().compile()
            return

        for qual in self.quals:
            try:
                location = ETHER["size"] + self.offset + IP[qual]
            except KeyError:
                pass
            if location is not None:
                break
        if location is None:
            raise ValueError(f"Invalid address type specifier {self.quals}")

        super().compile()

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

    def compile(self):
        '''Compile NOT - inverse true and false'''
        super().compile()
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
            self.left=attribs["frags"][1]
        self.attribs["name"] = "or"

    def compile(self):
        '''Compile OR - inverse true and false'''
        super().compile()
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
            self.left=attribs["frags"][1]

        self.attribs["name"] = "and"

class ProgramEncoder(json.JSONEncoder):
    '''Serializer to JSON'''

    def default(self, o):
        if isinstance(o, CBPFProgram):
            attribs = o.attribs.copy()
            attribs["quals"] = [*attribs["quals"]]
            try:
                attribs["labels"] = [*attribs["labels"]]
            except KeyError:
                pass
            return attribs
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
    "ipv4":ProgIPv4,
    "not":ProgNOT,
    "or":ProgOR,
    "and":ProgAND,
    "fail":ProgSuccess,
    "success":ProgFail
}
