''' Pure python implementation of the pcap language parser.
Compiler backends.
'''


#
# Copyright (c) 2023 Red Hat, Inc., Anton Ivanov <anivanov@redhat.com>
# Copyright (c) 2023 Cambridge Greys Ltd <anton.ivanov@cambridgegreys.com>
#

# SYMBOLIC REGISTER NAMES
RET = 'RET' # AX in (c|e)BPF

INS_PACK = Struct("=HBBI")

class cBPFIns(dict):
    def __init__(self, code, jt, jf, k):
        self.code = code
        self.jt = jt
        self.jf = jf
        self.k = k

    def compile(self):
        if isinstance(self.jt, dict) or isinstance(self.jf, dict) or isinstance(self.k, dict):
            raise ValueError("Unresolved reference")
        return INS_PACK(self.code, self.jt, self.jf, self.k)

    def __repr__(self):
        return "{} {}".format(self.code, self.k)

SIZE_MODS = {4 : "", 2 : "h", 1 : "b"}
FORMATS = [
    "x/%x",             # register x
    "[{}]",             # offset k in the packet
    "[x + {}]",         # offset k + x in the packet 
    "M[k]",             # offset k in M
    "#{}",               # k literal
    "4*([{}]&0xf)",     # Lower nibble * 4 at byte offset k in the packet ???
    "{}",               # Label
    "#{} {} {} ",       # #k, jt, jf
    "x/%x {} {}",       # x, jt, jf
    "#{} {}",           # #k, jt
    "x/%x {}",          # x, jt
    "a/%a",             # accumulator
    "{}"                # extensions
]

class AbstractCode(dict):
    '''Generic code class (bpf, instructions to flower, instructions
    to hardware, etc.
    '''
    def __init__(self, code="", reg="", size=4, mode=None):
        self.code = code + register
        self.code += SIZE_MODS[size]
        self.mode = mode
        self.values = []

    def __repr__(self):
        if mode is not None:
            return self.code + "\t" + FORMATS[self.mode].format(*self.values) 
        else:
            return self.code

    def check_mode(self, mode, mask):
        if not mode in mask:
            raise TypeError("Invalid Addressing mode")

class LD(AbstractCode):
    # Load into a register
    def __init__(self, values, reg="", size=4, mode=None):
        if reg == "x":
            check_mode(mode, [1, 2, 3, 4, 12])
        else:
            check_mode(mode, [3, 4, 5, 12])
        super().__init__(code="ld", reg=reg, size=size, mode=mode)
        self.values = values

class ST(AbstractCode):
    def __init__(self, values, reg="", size=4, mode=0):
        super().__init__(code="st", reg=reg, size=size, mode=3)
        self.values = values

class JMP(AbstractCode):
    def __init__(self, values):
        super().__init__(code="jmp", mode=6)
        self.values = values
        
class JA(AbstractCode):
    def __init__(self, values):
        super().__init__(code="ja", mode=6)
        self.values = values

class CondJump(AbstractCode):
    def __init__(self, values, code="jeq", mode=None):
        if code in ["jeq", "jgt", "jge", "jset"]:
            check_mode(mode, [7, 8, 9, 10])
        else:
            check_mode(mode, [9, 10])
        super().__init__(code=code, mode=mode)
        self.values = values
        
class JEQ(CondJump):
    def __init__(self, values, mode=None):
        super().__init__(values, code="jeq", mode=mode)
        
class JNEQ(CondJump):
    def __init__(self, values, mode=None):
        super().__init__(vlues, code="jneq", mode=mode)

class JNE(CondJump):
    def __init__(self, values, mode=None):
        super().__init__(values, code="jne", mode=mode)

class JLT(CondJump):
    def __init__(self, values, mode=None):
        super().__init__(values, code="jlt", mode=mode)

class JLE(CondJump):
    def __init__(self, values, mode=None):
        super().__init__(values, code="jlt", mode=mode)

class JGT(CondJump):
    def __init__(self, values, mode=None):
        super().__init__(values, code="jgt", mode=mode)

class JGE(CondJump):
    def __init__(self, values, mode=None):
        super().__init__(values, code="jge", mode=mode)a

class JSET(CondJump):
    def __init__(self, values, mode=None):
        super().__init__(values, code="jset", mode=mode)

class Arithmetics(AbstractCode):
    def __init__(self, values, code=None, mode=None):
        check_mode(mode, [0, 4])
        super().__init__(code=code, mode=mode)
        self.values = values

class ADD(Arithmetics):
    def __init__(self, values, mode=None):
        super().__init__(values, code="add", mode=mode)

class SUB(Arithmetics):
    def __init__(self, values, mode=None):
        super().__init__(values, code="sub", mode=mode)

class MUL(Arithmetics):
    def __init__(self, values, mode=None):
        super().__init__(values, code="mul", mode=mode)

class DIV(Arithmetics):
    def __init__(self, values, mode=None):
        super().__init__(values, code="div", mode=mode)

class MOD(Arithmetics):
    def __init__(self, values, mode=None):
        super().__init__(values, code="mod", mode=mode)

class AND(Arithmetics):
    def __init__(self, values, mode=None):
        super().__init__(values, code="and", mode=mode)

class OR(Arithmetics):
    def __init__(self, values, mode=None):
        super().__init__(values, code="or", mode=mode)

class XOR(Arithmetics):
    def __init__(self, values, mode=None):
        super().__init__(values, code="xor", mode=mode)

class LSH(Arithmetics):
    def __init__(self, values, mode=None):
        super().__init__(values, code="lsh", mode=mode)

class RSH(Arithmetics):
    def __init__(self, values, mode=None):
        super().__init__(values, code="rsh", mode=mode)

class NEG(AbstractCode):
    def __init__(self):
        super().__init__(None, code="neg")

class TAX(AbstractCode):
    def __init__(self):
        super().__init__(None, code="tax")

class TXA(AbstractCode):
    def __init__(self):
        super().__init__(None, code="txa")

class RET(AbstractCode):
    def __init__(self, values, mode=4):
        check_mode(mode, [4, 11])
        super().__init__(None, code="RET")

