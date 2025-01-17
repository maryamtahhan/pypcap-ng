''' Pure python implementation of the pcap language parser.
Compiler backends.
'''


#
# Copyright (c) 2023 Red Hat, Inc., Anton Ivanov <anivanov@redhat.com>
# Copyright (c) 2023 Cambridge Greys Ltd <anton.ivanov@cambridgegreys.com>
#

import sys
import struct
import re
import ipaddress
from header_constants import ETHER, IP, IP6, ETH_PROTOS
from code_objects import AbstractCode, AbstractHelper, NEXT_MATCH
from code_objects import FAIL, SUCCESS, LAST_INSN, Immediate, PARENT_NEXT


# Some of the names are predefined. They are instruction names. We
# should not change them.
#pylint: disable=line-too-long, invalid-name, consider-using-f-string


IPV4_REGEXP = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")


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

BPF_LD      =   0x00
BPF_LDX     =   0x01
BPF_ST      =   0x02
BPF_STX     =   0x03
BPF_ALU	    =   0x04
BPF_JMP     =   0x05
BPF_RET     =   0x06
BPF_MISC    =   0x07

# ld/ldx fields
# define BPF_SIZE(code)  ((code) & 0x18)
BPF_W       = 0x00      # 32-bit
BPF_H		= 0x08      # 16-bit
BPF_B	    = 0x10      # 8-bit
#eBPF		BPF_DW		0x18    64-bit

#define BPF_MODE(code)  ((code) & 0xe0)

BPF_IMM		=   0x00 # 4
BPF_ABS		=   0x20 # 1
BPF_IND		=   0x40 # 2
BPF_MEM		=   0x60 # 3
BPF_LEN		=   0x80 # packet length - special
BPF_MSH		=   0xa0 # 5

# alu/jmp fields
# define BPF_OP(code)    ((code) & 0xf0)
BPF_ADD		=   0x00
BPF_SUB		=   0x10
BPF_MUL		=   0x20
BPF_DIV		=   0x30
BPF_OR		=   0x40
BPF_AND		=   0x50
BPF_LSH		=   0x60
BPF_RSH		=   0x70
BPF_NEG		=   0x80
BPF_MOD		=   0x90
BPF_XOR		=   0xa0

BPF_JA		=   0x00
BPF_JEQ		=   0x10
BPF_JGT		=   0x20
BPF_JGE		=   0x30
BPF_JSET    =   0x40
#BPF_SRC(code)   ((code) & 0x08)
BPF_K		=   0x00
BPF_X		=   0x08


#define BPF_MISCOP(code) ((code) & 0xf8)
BPF_TAX     =   0x00
BPF_TXA     =   0x80

PACKER = struct.Struct(r"=HBBI")

class CBPFCompilerState():
    '''CBPF Specific compiler state'''

    def __init__(self):
    #pylint: disable=unused-variable
        self.regfile = []
        for index in range(0,16):
            self.regfile.append(True)
        self.offsets = {}
        self.quals = []

    def next_free_reg(self):
        '''Next available reg in the scratch space'''
        for reg in self.regfile:
            if self.regfile[reg]:
                self.regfile[reg] = False
                return reg
        raise IndexError("No free scratch registers")

    def get_offset(self, elements=None):
        '''Compute offsets for given header elements'''
        total = 0
        if isinstance(elements, str):
            elements = set([elements])
        for key, value in self.offsets.items():
            if elements is None:
                total += value
            elif key in elements:
                total += value
        return total

    def set_offset(self, element, value):
        '''Compute offsets for given header elements'''
        self.offsets[element] = value

    def add_offset(self, element, value):
        '''Compute offsets for given header elements'''
        try:
            self.offsets[element] += value
        except KeyError:
            self.offsets[element] = value

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
SIZE_OBJ_MODS = [0, 0x10, 0x8, 0, 0]
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

ADDR_OBJ_MODS = [BPF_X, BPF_ABS, BPF_IND, BPF_MEM, BPF_IMM, BPF_MSH, 0, 0, 0, 0, 0, 0, 0]

class CBPFCode(AbstractCode):
    '''BPF variant of code generation'''
    def __init__(self, code="", reg="", size=4, mode=0, label=None):
        super().__init__(label=label)
        self.code = code + reg
        self.code += SIZE_MODS[size]
        self.mode = mode
        self.reg = reg
        self.size = size
        self.opcode_class = 0

    def __eq__(self, other):
        '''Equal - needed for tests'''
        return super().__eq__(other) and self.code == other.code and \
               self.values == other.values and self.mode == other.mode

    def obj_dump(self, counter):
        '''Dump bytecode'''

        bpf_jt = 0
        bpf_jf = 0
        value = 0
        try:
            value = self.values[0]
        except IndexError:
            pass

        try:
            if self.opcode_class & 0x7 == 5:
                bpf_jt = self.values[1] - counter - 1
                bpf_jf = self.values[2] - counter - 1
        except TypeError as exc:
        #pylint: disable=consider-using-f-string
            raise ValueError(
                "Unresolved references jt {} jf {}".format(self.values[1], self.values[2])
            ) from exc

        if self.opcode_class in [BPF_MISC+BPF_TAX, BPF_MISC+BPF_TXA]:
            opcode = self.opcode_class
        else:
            opcode = self.opcode_class + SIZE_OBJ_MODS[self.size] + ADDR_OBJ_MODS[self.mode]

        if bpf_jt > 255 or bpf_jf > 255:
            raise ValueError(f"A jump of {bpf_jt} {bpf_jf} is a jump too far")
        return (opcode, bpf_jt, bpf_jf, value)

    def __str__(self):
        '''Same as repr'''
        return self.__repr__()

    def __repr__(self):
        '''Printable form of BPF instructions'''
        res = ":\n".join(self.labels)

        res += "\t" + self.code

        if self.code in ["tax", "txa"]:
            return res

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
    '''Load into A'''
    def __init__(self, values, size=4, mode=None, label=None):
        self.check_mode(mode, [1, 2, 3, 4, 12])
        super().__init__(code="ld", reg="", size=size, mode=mode, label=label)
        self.set_values(values)
        self.opcode_class = 0x0

class LDX(CBPFCode):
    '''Load into X'''
    def __init__(self, values, size=4, mode=None, label=None):
        self.check_mode(mode, [3, 4, 5, 12])
        super().__init__(code="ld", reg="x", size=size, mode=mode, label=label)
        self.set_values(values)
        self.opcode_class = 0x1


class ST(CBPFCode):
    '''Store from A'''
    def __init__(self, values, reg="", size=4, mode=0, label=None):
        super().__init__(code="st", reg=reg, size=size, mode=mode, label=label)
        self.check_mode(mode, [3])
        self.set_values(values)
        self.opcode_class = 0x2

class STX(CBPFCode):
    '''Store from X'''
    def __init__(self, values, reg="", size=4, mode=0, label=None):
        super().__init__(code="st", reg=reg, size=size, mode=mode, label=label)
        self.check_mode(mode, [3])
        self.set_values(values)
        self.opcode_class = 0x3


class Jump(CBPFCode):
    '''Generic Jump.'''
    def __init__(self, code=None, values=None, mode=6, label=None, size=4):
        super().__init__(code=code, mode=mode, label=label)
        self.set_values(values)
        self.opcode_class = 0x5

    def resolve_refs(self, old_label, new_label):
        '''Update refs'''
        #pylint: disable=consider-using-enumerate
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
        self.opcode_class += BPF_JEQ

def JNEQ(values, mode=None, label=None, size=4):
    '''Emulate JNEQ via inverse JEQ'''
    tmp = values[0]
    values[0] = values[1]
    values[1] = tmp
    return JEQ(values, mode=mode, label=label, size=size)

def JNE(values, mode=None, label=None, size=4):
    '''Ditto - emulate JNE'''
    return JNEQ(values, mode=mode, label=label, size=size)

def JLT(values, mode=None, label=None, size=4):
    '''Emulate JLT via JGE'''
    tmp = values[0]
    values[0] = values[1]
    values[1] = tmp
    return JGE(values, mode=mode, label=label, size=size)

def JLE(values, mode=None, label=None, size=4):
    '''Emulate JLT via JGE'''
    tmp = values[0]
    values[0] = values[1]
    values[1] = tmp
    return JGT(values, mode=mode, label=label, size=size)

class JGT(CondJump):
    '''Jump on greater'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="jgt", mode=mode, label=label, size=size)
        self.opcode_class += BPF_JGT

class JGE(CondJump):
    '''Jump on greater or equal'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="jge", mode=mode, label=label, size=size)
        self.opcode_class += BPF_JGE

class JSET(CondJump):
    '''Jump on a set bit'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="jset", mode=mode, label=label, size=size)
        self.opcode_class += BPF_JSET

class Arithmetics(CBPFCode):
    '''Generic arithmetic instruction'''
    def __init__(self, values, code=None, mode=None, label=None, size=4):
        self.check_mode(mode, [0, 4])
        super().__init__(code=code, mode=mode, label=label, size=size)
        self.set_values(values)
        self.opcode_class += BPF_ALU

class ADD(Arithmetics):
    '''ADD instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="add", mode=mode, label=label, size=size)
        self.opcode_class += BPF_ADD

class SUB(Arithmetics):
    '''SUB instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="sub", mode=mode, label=label, size=size)
        self.opcode_class += BPF_SUB

class MUL(Arithmetics):
    '''MUL instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="mul", mode=mode, label=label, size=size)
        self.opcode_class += BPF_MUL

class DIV(Arithmetics):
    '''DIV instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="div", mode=mode, label=label, size=size)
        self.opcode_class += BPF_DIV

class MOD(Arithmetics):
    '''MOD instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="mod", mode=mode, label=label, size=size)
        self.opcode_class += BPF_MOD

class AND(Arithmetics):
    '''Arithmetic AND instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="and", mode=mode, label=label, size=size)
        self.opcode_class += BPF_AND

class OR(Arithmetics):
    '''Arithmetic OR instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="or", mode=mode, label=label, size=size)
        self.opcode_class += BPF_OR

class XOR(Arithmetics):
    '''Arithmetic XOR instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="xor", mode=mode, label=label, size=size)
        self.opcode_class += BPF_XOR

class LSH(Arithmetics):
    '''LSH instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="lsh", mode=mode, label=label, size=size)
        self.opcode_class += BPF_LSH

class RSH(Arithmetics):
    '''RSH instruction'''
    def __init__(self, values, mode=None, label=None, size=4):
        super().__init__(values, code="rsh", mode=mode, label=label, size=size)
        self.opcode_class += BPF_RSH

class NEG(CBPFCode):
    '''NEG instruction'''
    def __init__(self, label=None, size=4):
        super().__init__(code="neg", label=label, size=size)
        self.opcode_class += BPF_NEG

class TAX(CBPFCode):
    '''Transfer A to X'''
    def __init__(self, label=None, size=4):
        super().__init__(code="tax", label=label, size=size)
        self.opcode_class = BPF_MISC+BPF_TAX


class TXA(CBPFCode):
    '''Transfer X to A'''
    def __init__(self, label=None, size=4):
        super().__init__(code="txa", label=label, size=size)
        self.opcode_class = BPF_MISC+BPF_TXA

class RET(CBPFCode):
    '''RET with result.
       cBPF convention is 0 for failure and non
       negative packet "size" for success
    '''
    def __init__(self, values, mode=4, label=None, size=4):
        self.check_mode(mode, [4, 11])
        super().__init__(code="ret", mode=mode, label=label, size=size)
        self.set_values(values)
        self.opcode_class = BPF_RET


V4_NET_REGEXP = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})")

class CBPFHelper(AbstractHelper):
    '''cBPF variant of AbstractHelper'''
    def __init__(self, pcap_obj):
        super().__init__(pcap_obj)
        self.helper_id = "cbpf"
        self.stashed_in = None

    @property
    def offset(self):
        '''match_object getter'''
        try:
            return self.attribs["offset"]
        except KeyError:
            return 0

    def dump_code(self, fmt, options):
        '''Dump BPF'''

        super().dump_code(fmt, options)

        res = ""
        if fmt == "asm":
            linenum = 0
            for ins in self.get_code():
                if "lines" in options:
                    linenum += 1
                    res += f"{linenum} {ins}\n"
                else:
                    res += f"{ins}\n"

        if fmt == "iptables":
            res += "{}".format(len(self.get_code()))
            counter = 0
            for ins in self.get_code():
                res += ", {} {} {} {}".format(*ins.obj_dump(counter))
                counter += 1
            res += "\n"
        return res



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

    @property
    def ip_version(self):
        '''right getter'''
        return self.pcap_obj.ip_version

    def add_code(self, code):
        '''Invoke pcap obj add_code'''
        self.pcap_obj.add_code(code, self.helper_id)

    def add_offset_code(self, code):
        '''Invoke pcap obj add_code'''
        self.pcap_obj.add_offset_code(code, self.helper_id)

# These are way too cBPF specific to try to make them into generic instances

class CBPFAbstractProgram(CBPFHelper):
    '''Do nothing - attaches to a program which just calls subs.
    '''

class CBPFProgSuccess(CBPFHelper):
    '''Success
    '''
    def compile(self, compiler_state=None):
        super().compile(compiler_state)
        self.add_code([RET(0xFFFF, label=[SUCCESS])])

class CBPFProgFail(CBPFHelper):
    '''Fail
    '''
    def compile(self, compiler_state=None):
        super().compile(compiler_state)
        self.add_code([RET(0, label=[LAST_INSN, FAIL])])


class CBPFProgL2(CBPFHelper):
    '''Basic L2 Match
    '''

    def compile(self, compiler_state=None):

        super().compile(compiler_state)
        compiler_state.set_offset("L2", ETHER["size"])

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

        return compiler_state.get_offset("L2")


class CBPFProg8021Q(CBPFHelper):
    '''Vlan matcher'''
    def compile(self, compiler_state=None):

        super().compile(compiler_state)
        compiler_state.add_offset("L2T", 4)
        self.add_code([
            LD(self.offset + compiler_state.get_offset("L2") + 2, size=2, mode=1),
            AND(0xFFF, mode=4),
            JEQ([self.match_object, self.on_success, self.on_failure], mode=7)
        ])

    def compile_offsets(self, compiler_state=None):
        '''802.1q offset'''
        return compiler_state.get_offset(["L2", "L2T"])


PORT = {
    "src": 0,
    "dst": 2
}

class CBPFProgL3(CBPFHelper):
    '''Layer 3 protocol matcher'''
    def compile(self, compiler_state=None):
        '''Compile the code'''

        super().compile(compiler_state)
        self.add_code([
            LD(self.offset + compiler_state.get_offset(["L2", "L2T"]) + IP["proto"], size=1, mode=1),
            JEQ([self.match_object, self.on_success, self.on_failure], mode=7),
        ])

class CBPFProgIP(CBPFHelper):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''

    def compile(self, compiler_state=None):
        '''We need to check IP version. As a side effect
           This also deals with references after an L2 trim.
        '''
        super().compile(compiler_state=None)
        self.add_code([
            LD(self.offset + compiler_state.get_offset(["L2", "L2T"]), size=1, mode=1),
            RSH(4, mode=4),
            JEQ([int(self.ip_version), self.on_success, self.on_failure], mode=7),
        ])


    def compile_offsets(self, compiler_state=None):
        '''Compile offset past IP Headers'''

        super().compile_offsets(compiler_state)

        if int(self.ip_version) == 4:
            self.add_offset_code([
                LDX([compiler_state.get_offset(["L2", "L2T"])], size=1, mode=5)
            ])
        else:
            compiler_state.set_offset("L3", 40)

class CBPFProgTCP(CBPFProgL3):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''

    def compile_offsets(self, compiler_state=None):
        '''Compile offset past IP Headers'''
        super().compile_offsets(compiler_state)

        self.add_offset_code([
            LD([compiler_state.get_offset(["L2", "L2T", "L3"]) + 12], size=1, mode=2),
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
            LDX([compiler_state.get_offset(["L2", "L2T", "L3"])], size=1, mode=5)
        ]

        if self.pcap_obj.frags[0].result is None:
            self.stashed_in = compiler_state.next_free_reg()
            self.add_code([ST([self.stashed_in], mode=3)])

        self.compile_offsets(compiler_state)

        if "src" in self.pcap_obj.quals:
            code.append(
                LD([compiler_state.get_offset(["L2", "L2T", "L3"])], size=2, mode=2),
            )
        if "dst" in self.pcap_obj.quals:
            code.append(
                LD([compiler_state.get_offset(["L2", "L2T", "L3"]) + 2], size=2, mode=2),
            )

        if self.pcap_obj.frags[0].result is None:
            code.append(LDX([self.stashed_in], mode=3))
            code.append(JEQ([self.on_success, self.on_failure], mode=8))
            compiler_state.release(self.stashed_in)
        else:
            code.append(JEQ([self.pcap_obj.frags[0].result, self.on_success, self.on_failure], mode=7))
            # add labels for immediate ops to self
        self.add_code(code)
        self.pcap_obj.get_code(self.helper_id)[0].add_label("__start__{}".format(self.frags[0].loc))
        self.pcap_obj.get_code(self.helper_id)[-1].add_label("__end__{}".format(self.frags[-1].loc))

class CBPFProgPortRange(CBPFHelper):
    '''Portrange.
    '''
    def compile(self, compiler_state=None):
        '''Compile the code'''

        code = []

        super().compile(compiler_state)

        left = self.attribs["loc"][0]
        right = self.attribs["loc"][1]

        left_stash = None
        right_stash = None

        left.compile(compiler_state)

        if left.result is None:
            left_stash = compiler_state.next_free_reg()
            left.add_code([ST([left_stash], mode=3)], self.helper_id)
            self.add_code(left.get_code(self.helper_id))

        right.compile(compiler_state)

        if right.result is None:
            right_stash = compiler_state.next_free_reg()
            right.add_code([ST([right_stash], mode=3)], self.helper_id)
            self.add_code(right.code)

        self.compile_offsets(compiler_state)

        if "src" in self.pcap_obj.quals:
            code.append(
                LD([compiler_state.get_offset(["L2", "L2T", "L3"])], size=2, mode=2)
            )

        if "dst" in self.pcap_obj.quals:
            code.append(
                LD([compiler_state.get_offset(["L2", "L2T", "L3"]) + 2], size=2, mode=2)
            )

        if left_stash is not None:
            code.append(LDX([left_stash], mode=3))
            code.append(JGE([self.on_success, self.on_failure], mode=8))
            compiler_state.release(left_stash)
        else:
            code.append(JGE([left.result, f"_portrange_next_{self.loc}", self.on_failure], mode=7))

        if right_stash is not None:
            code.append(LDX([right_stash], mode=3, label=f"_portrange_next_{self.loc}"))
            code.append(JGT([self.on_failure, self.on_success], mode=8))
            compiler_state.release(right_stash)
        else:
            code.append(JGT([right.result, self.on_failure, self.on_success], mode=7, label=f"_portrange_next_{self.loc}"))

        self.add_code(code)
        self.pcap_obj.get_code(self.helper_id)[0].add_label("__start__{}".format(self.frags[0].loc))
        self.pcap_obj.get_code(self.helper_id)[-1].add_label("__end__{}".format(self.frags[-1].loc))


class CBPFProgIPv4(CBPFHelper):
    '''Basic match on v4 address or network.
    '''
    def compile(self, compiler_state=None):
        '''Generate the actual code for the match'''
        try:
            addr = ipaddress.ip_address(self.match_object)
        except ValueError:
            # we let it raise a value error in this case
            addr = ipaddress.ip_network(self.match_object)

        # we do not do any further checks, because regexps
        # should narrow the input to ip_address sufficiently
        # to guarantee a v4 of some sort.

        location = None

        super().compile(compiler_state)

        if "srcordst" in self.pcap_obj.quals or "srcanddst" in self.pcap_obj.quals:
            return

        for qual in self.pcap_obj.quals:
            # Use only simple qualifiers. Skip protos, vlans, etc

            if isinstance(qual, str):
                try:
                    location = compiler_state.get_offset(["L2", "L2T"]) + self.offset + IP[qual]
                except KeyError:
                    pass
                if location is not None:
                    break
        if location is None:
            raise ValueError(f"Invalid address type specifier {self.pcap_obj.quals}")


        code = [LD(location, size=4, mode=1)]
        if isinstance(addr, ipaddress.IPv4Network):
            code.extend([
                AND(int(addr.netmask), mode=4),
                JEQ([int(addr.network_address), self.on_success, self.on_failure], mode=7)
            ])
        else:
            code.append(JEQ([int(addr), self.on_success, self.on_failure], mode=7))
        self.add_code(code)

class CBPFProgIPv6(CBPFHelper):
    '''Basic match on v4 address or network.
    '''
    def compile(self, compiler_state=None):
        '''Generate the actual code for the match'''
        try:
            addr = ipaddress.ip_address(self.match_object)
        except ValueError:
            # we let it raise a value error in this case
            addr = ipaddress.ip_network(self.match_object)

        location = None

        super().compile(compiler_state)

        if "srcordst" in self.pcap_obj.quals or "srcanddst" in self.pcap_obj.quals:
            return

        for qual in self.pcap_obj.quals:
            # Use only simple qualifiers. Skip protos, vlans, etc

            if isinstance(qual, str):
                try:
                    location = compiler_state.get_offset(["L2", "L2T"]) + self.offset + IP6[qual]
                except KeyError:
                    pass
                if location is not None:
                    break
        if location is None:
            raise ValueError(f"Invalid address type specifier {self.pcap_obj.quals}")

        code = []


        if isinstance(addr, ipaddress.IPv6Network):
            netmask = int(addr.netmask).to_bytes(16, byteorder='big')
            address = int(addr.network_address).to_bytes(16, byteorder='big')

            for nibble in range(0,4):
                if nibble < 3:
                    next_label = "_v6_{}_{}".format(self.loc, nibble + 1)
                else:
                    next_label = self.on_success
                code.extend([
                    LD(location + nibble * 4, size=4, mode=1, label=f"_v6_{self.loc}_{nibble}"),
                    AND(int.from_bytes(netmask[nibble*4:nibble*4 + 4]), mode=4),
                    JEQ([int.from_bytes(address[nibble*4:nibble*4 + 4]), next_label, self.on_failure], mode=7)
                ])
        else:
            address = int(addr).to_bytes(16, byteorder=big)
            for nibble in range(0,4):
                if nibble < 3:
                    next_label = "_v6_{}_{}".format(self.loc, nibble + 1)
                else:
                    next_label = self.on_success
                code.extend([
                    LD(location + nibble * 4, size=4, mode=1, label=f"_v6_{self.loc}_{nibble}"),
                    JEQ([int.from_bytes(address[nibble*4:nibble*4 + 4]), next_label, self.on_failure], mode=7)
                ])
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
        offsets = compiler_state.offsets
        self.left.compile(compiler_state)
        compiler_state.quals = old_state
        compiler_state.offsets = offsets
        self.right.compile(compiler_state)

        label = self.frags[1].get_start_label()

        self.frags[0].replace_value(NEXT_MATCH, PARENT_NEXT)
        self.frags[0].replace_value(FAIL, label)


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

        code = self.pcap_obj.get_offset_code(self.helper_id)
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
        self.pcap_obj.get_code(self.helper_id)[0].add_label("__start__{}".format(self.frags[0].loc))
        self.pcap_obj.get_code(self.helper_id)[-1].add_label("__end__{}".format(self.frags[-1].loc))

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
            left.add_code([ST([self.stashed_in], mode=3)], self.helper_id)

        if left.result is None and right.result is None:
            self.add_code([
                LDX([self.left.stashed_in], mode=3),
                COMP_TABLE[self.attribs["op"]]([self.stashed_in, self.on_success, self.on_failure], mode=3)
            ])

        if left.result is not None and right.result is None:
            self.add_code([COMP_TABLE[self.attribs["op"]]([left.result, self.on_success, self.on_failure], mode=7)])

        if left.result is None and right.result is not None:
            if stashed_in is not None:
                left.code[self.helper_id].pop()
            self.add_code([COMP_TABLE[self.attribs["op"]]([right.result, self.on_success, self.on_failure], mode=7)])

        if left.result is not None and right.result is not None:
            self.pcap_obj.result = compute(left.result, self.attribs["op"], right.result)
            if self.pcap_obj.result:
                self.add_code(JMP([self.on_success]))
            else:
                self.add_code(JMP([self.on_failure]))

        if stashed_in is not None:
            compiler_state.release(stashed_in)
        self.pcap_obj.get_code(self.helper_id)[0].add_label("__start__{}".format(self.frags[0].loc))
        self.pcap_obj.get_code(self.helper_id)[-1].add_label("__end__{}".format(self.frags[-1].loc))

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
            left.add_code([ST([self.stashed_in], mode=3)], self.helper_id)
            self.add_code([
                    LDX([stashed_in], mode=3),
                    ARITH_TABLE[self.attribs["op"]](mode=0)
                ])

        if left.result is not None and right.result is None:
            self.add_code([ARITH_TABLE[self.attribs["op"]]([left.result], mode=4)])

        if left.result is None and right.result is not None:
            if stashed_in is not None:
                left.code[self.helper_id].pop()
            self.add_code([ARITH_TABLE[self.attribs["op"]]([right.result], mode=4)])

        if self.left.result is not None and self.right.result is not None:
            if stashed_in is not None:
                left.code[self.helper_id].pop()
            self.pcap_obj.result = compute(left.result, self.attribs["op"], right.result)

        if stashed_in is not None:
            compiler_state.release(stashed_in)
        self.pcap_obj.get_code(self.helper_id)[0].add_label("__start__{}".format(self.frags[0].loc))
        self.pcap_obj.get_code(self.helper_id)[-1].add_label("__end__{}".format(self.frags[-1].loc))

def dispatcher(obj):
    '''Return the correct code helper'''
    return getattr(sys.modules[__name__], f"CBPF{obj.__class__.__name__}")(obj)
