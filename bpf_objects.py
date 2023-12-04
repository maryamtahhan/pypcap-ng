''' Pure python implementation of the pcap language parser.
Compiler backends.
'''


#
# Copyright (c) 2023 Red Hat, Inc., Anton Ivanov <anivanov@redhat.com>
# Copyright (c) 2023 Cambridge Greys Ltd <anton.ivanov@cambridgegreys.com>
#

import sys
import re
from header_constants import ETHER, IP, ETH_PROTOS, IP_PROTOS
from code_objects import AbstractCode, AbstractHelper, NEXT_MATCH, FAIL, SUCCESS, LAST_INSN, Immediate


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

class CBPFHelper(AbstractHelper):
    '''cBPF variant of AbstractHelper'''
    def __init__(self, pcap_obj):
        super().__init__(pcap_obj)
        self.stashed_in = None

    @property
    def offset(self):
        '''match_object getter'''
        try:
            return self.attribs["offset"]
        except KeyError:
            return 0
    

    @property
    def loc(self):
        '''match_object getter'''
        return self.pcap_obj.loc


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

    @property
    def attribs(self):
        '''frags getter'''
        return self.pcap_obj.attribs

    @property
    def frags(self):
        '''frags getter'''
        return self.pcap_obj.frags

    @property
    def left(self):
        '''left getter'''
        return self.pcap_obj.left

    @property
    def right(self):
        '''right getter'''
        return self.pcap_obj.right

    def add_code(self, code):
        '''Invoke pcap obj add_code'''
        self.pcap_obj.add_code(code)

    def add_offset_code(self, code):
        '''Invoke pcap obj add_code'''
        self.pcap_obj.add_offset_code(code)

# These are way too cBPF specific to try to make them into generic instances

class CBPFAbstractProgram(CBPFHelper):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''

class CBPFProgSuccess(CBPFHelper):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def compile(self, compiler_state=None):
        super().compile(compiler_state)
        self.add_code([RET(0xFFFF, label=[SUCCESS])])

class CBPFProgFail(CBPFHelper):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def compile(self, compiler_state=None):
        super().compile(compiler_state)
        self.add_code([RET(0, label=[LAST_INSN, FAIL])])


class CBPFProgL2(CBPFHelper):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''

    def compile(self, compiler_state=None):

        super().compile(compiler_state)
        compiler_state.offset = ETHER["size"]

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

    def compile_offsets(self, compiler_state=None):
        '''L2 offset'''
        super().compile_offsets(compiler_state)

        return ETHER["size"]


class CBPFProg8021Q(CBPFHelper):
    '''Vlan matcher'''
    def compile(self, compiler_state=None):

        super().compile(compiler_state)
        compiler_state.offset = ETHER["size"] + 4
        self.add_code([
            LD(self.offset + ETHER["size"] + 2, size=2, mode=1),
            AND(0x3F, mode=4),
            JEQ([self.match_object, self.on_success, self.on_failure], mode=7)
        ])

    def compile_offsets(self, compiler_state=None):
        '''802.1q offset'''
        return super().compile_offsets(compiler_state) + 4


class CBPFProgL3(CBPFHelper):
    '''Layer 3 protocol matcher'''
    def compile(self, compiler_state=None):
        '''Compile the code'''

        super().compile(compiler_state)
        self.add_code([
            LD(self.offset + compiler_state.offset + IP["proto"], size=1, mode=1),
            JEQ([self.match_object, self.on_success, self.on_failure], mode=7),
        ])

PORT = {
    "src": 0,
    "dst": 2
}

class CBPFProgIP(CBPFHelper):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''

    def compile_offsets(self, compiler_state=None):
        '''Compile offset past IP Headers'''
        super().compile_offsets(compiler_state)
        self.add_offset_code([
            LD([compiler_state.offset], size=1, mode=5, reg="x")
        ])

class CBPFProgTCP(CBPFHelper):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def compile_offsets(self, compiler_state=None):
        '''Compile offset past IP Headers'''
        super().compile_offsets(compiler_state)

        self.add_offset_code([
            LD([compiler_state.offset + 12], size=1, mode=2),
            RSH([2], mode=4),
            ADD([], mode=0),
            TAX(),
        ])


class CBPFProgPort(CBPFHelper):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def compile(self, compiler_state=None):
        '''Compile the code'''

        super().compile(compiler_state)

        code = [
            LD([compiler_state.offset], size=1, mode=5, reg="x")
        ]

        if self.pcap_obj.frags[0].result is None:
            self.stashed_in = compiler_state.next_free_reg()
            self.add_code([ST([self.stashed_in], mode=3)])

        self.compile_offsets(compiler_state)

        if "src" in self.pcap_obj.quals:
            code.append(
                LD([compiler_state.offset], size=2, mode=2),
            )
        if "dst" in self.pcap_obj.quals:
            code.append(
                LD([compiler_state.offset + 2], size=2, mode=2),
            )

        if self.pcap_obj.frags[0].result is None:
            code.append(LD([self.stashed_in], reg="x", mode=3))
            code.append(JEQ([self.on_success, self.on_failure], mode=8))
            compiler_state.release(self.stashed_in)
        else:
            code.append(JEQ([self.pcap_obj.frags[0].result, self.on_success, self.on_failure], mode=7))
        self.add_code(code)

class CBPFProgIPv4(CBPFHelper):
    '''Basic match on v4 address or network.
    '''
    def compile(self, compiler_state=None):
        '''Generate the actual code for the match'''

        addr = V4_NET_REGEXP.match(self.match_object)
        location = None

        super().compile(compiler_state)

        if "srcordst" in self.pcap_obj.quals or "srcanddst" in self.pcap_obj.quals:
            return

        for qual in self.pcap_obj.quals:
            # Use only simple qualifiers. Skip protos, vlans, etc

            if isinstance(qual, str):
                try:
                    location = compiler_state.offset + self.offset + IP[qual]
                except KeyError:
                    pass
                if location is not None:
                    break
        if location is None:
            raise ValueError(f"Invalid address type specifier {self.pcap_obj.quals}")


        code = [LD(location, size=4, mode=1)]
        if addr is not None:
            netmask = 0xffffffff ^ (0xffffffff >> int(addr.group(2)))
            code.extend([AND(netmask, mode=4), JEQ([ipv4_to_word(addr.group(1)), self.on_success, self.on_failure], mode=7)])
        else:
            code.append(JEQ([ipv4_to_word(self.match_object), self.on_success, self.on_failure], mode=7))
        self.add_code(code)


class CBPFProgNOT(CBPFHelper):
    '''Negate the result of all frags.
    '''
    def compile(self, compiler_state=None):
        '''Compile NOT - inverse true and false'''
        super().compile(compiler_state)
        self.pcap_obj.replace_value(NEXT_MATCH, "__temp_not")
        self.pcap_obj.replace_value(FAIL, NEXT_MATCH)
        self.pcap_obj.replace_value("__temp_not", FAIL)


class CBPFProgOR(CBPFHelper):
    '''Perform logical OR on left and right frag(s)
    '''
    def compile(self, compiler_state=None):
        '''Compile OR - inverse true and false'''

        old_state = compiler_state.quals.copy()
        offset = compiler_state.offset
        self.left.compile(compiler_state)
        compiler_state.quals = old_state
        compiler_state.offset = offset
        self.right.compile(compiler_state)

        self.frags[0].replace_value(self.frags[1].get_start_label(), NEXT_MATCH)
        self.frags[0].replace_value(FAIL, self.frags[1].get_start_label())


class CBPFProgAND(CBPFHelper):
    '''Perform logical AND on left and right frag(s)
    '''

COMP_TABLE = {
    "<" : JLT,
    ">" : JGT,
    "==" : JEQ,
    "!=" : JNEQ,
    ">=" : JGE,
    "<=" : JLE
}

class CBPFProgOffset(CBPFHelper):
    '''Perform computation of offset to payload
    '''

    def compile(self, compiler_state=None):
        '''We compile offset code instead of the normal
           match logic.
        '''

        super().compile(compiler_state)
        self.pcap_obj.compile_offsets(compiler_state)

        code = self.pcap_obj.get_offset_code()
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


class CBPFProgLoad(CBPFHelper):
    '''Load a value from packet address
    '''
    def compile(self, compiler_state=None):
        '''Compile arithmetics'''

        super().compile(compiler_state)

        super().compile_offsets(compiler_state)

        if isinstance(self.pcap_obj.attribs["loc"], Immediate):
            if self.pcap_obj.use_offset:
                self.add_code([LD([self.pcap_obj.attribs["loc"].attribs["match_object"] + compiler_state.offset], size=self.pcap_obj.attribs["size"], mode=2)])
            else:
                self.add_code([LD([self.pcap_obj.attribs["loc"].attribs["match_object"] + compiler_state.offset], size=self.pcap_obj.attribs["size"], mode=1)])

class CBPFProgIndexLoad(CBPFHelper):
    '''Perform arithmetic operations.
    '''

    def compile(self, compiler_state=None):
        '''Compile arithmetics'''
        super().compile(compiler_state)
        self.add_code([
            TAX(),
            LD([0], size=self.pcap_obj.attribs["size"], mode=2)
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


class CBPFProgComp(CBPFHelper):
    '''Perform arithmetic comparisons.
    '''

    def compile(self, compiler_state=None):
        '''Compile comparison between operands'''

        left = self.pcap_obj.left
        right = self.pcap_obj.right
        stashed_in = None

        super().compile(compiler_state)

        if left.result is None:
            stashed_in = compiler_state.next_free_reg()
            left.add_code([ST([self.stashed_in], mode=3)])

        if left.result is None and right.result is None:
            self.add_code([
                LD([self.left.stashed_in], reg="x", mode=3),
                COMP_TABLE[self.attribs["op"]]([self.stashed_in, self.on_success, self.on_failure], mode=3)
            ])

        if left.result is not None and right.result is None:
            self.add_code([COMP_TABLE[self.attribs["op"]]([left.result, self.on_success, self.on_failure], mode=7)])

        if left.result is None and right.result is not None:
            if stashed_in is not None:
                left.code.pop()
            self.add_code([COMP_TABLE[self.attribs["op"]]([right.result, self.on_success, self.on_failure], mode=7)])

        if left.result is not None and right.result is not None:
            self.pcap_obj.result = compute(left.result, self.attribs["op"], right.result)
            if self.pcap_obj.result:
                self.add_code(JMP([self.on_success]))
            else:
                self.add_code(JMP([self.on_failure]))

        if stashed_in is not None:
            compiler_state.release(stashed_in)

class CBPFImmediate(CBPFHelper):
    '''Fake leafe for immediate ops
    '''
    def compile(self, compiler_state=None):
        self.pcap_obj.result = self.match_object


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

class CBPFProgArOp(CBPFHelper):
    '''Perform arithmetic operations.
    '''

    def compile(self, compiler_state=None):
        '''Compile arithmetics'''

        left = self.pcap_obj.left
        right = self.pcap_obj.right
        stashed_in = None

        super().compile(compiler_state)

        if left.result is None and right.result is None:
            stashed_in = compiler_state.next_free_reg()
            self.add_code([
                    LD([stashed_in], reg="x", mode=3),
                    ARITH_TABLE[self.attribs["op"]](mode=0)
                ])

        if left.result is not None and right.result is None:
            self.add_code([ARITH_TABLE[self.attribs["op"]]([left.result], mode=4)])

        if left.result is None and right.result is not None:
            if stashed_in is not None:
                left.code.pop()
            self.add_code([ARITH_TABLE[self.attribs["op"]]([right.result], mode=4)])

        if self.left.result is not None and self.right.result is not None:
            if stashed_in is not None:
                left.code.pop()
            self.pcap_obj.result = compute(left.result, self.attribs["op"], right.result)

        if stashed_in is not None:
            compiler_state.release(stashed_in)

def dispatcher(obj):
    '''Return the correct code helper'''
    return getattr(sys.modules[__name__], f"CBPF{obj.__class__.__name__}")(obj)
