''' Pure python implementation of the pcap language parser.
Compiler backends.
'''


#
# Copyright (c) 2023 Red Hat, Inc., Anton Ivanov <anivanov@redhat.com>
# Copyright (c) 2023 Cambridge Greys Ltd <anton.ivanov@cambridgegreys.com>
#

from struct import Struct
import re
import parser
from parsed_tree import LEFT, RIGHT, OP, OBJ, QUALS, OBJTYPE, PROTO
from header_constants import ETHER, IP, ETH_PROTOS, IP_PROTOS

# SYMBOLIC REGISTER NAMES
RET = 'RET' # AX in (c|e)BPF

INS_PACK = Struct("=HBBI")

IPV4_REGEXP = re.compile("(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")

class CompilerState():
    def __init__(self):
        self.loc = 0

    def get_loc(self):
        self.loc += 1
        return self.loc

COMPILER_STATE = CompilerState()

def IPv4toWord(ipv4):
    match = IPV4_REGEXP.match(ipv4)
    if match is not None:
        scale = 24
        total = 0
        for index in range(1,4):
            nibble = int(match.group(index))
            if nibble > 256 or nibble < 0:
                raise TypeError("Invalid IP address")
            total += nibble << scale
            scale -= 8
        return total
    raise TypeError("Invalid IP address")
            
            

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

FORMATS = [
    "x/%x",                 # 0  register x
    "[{:04X}]",             # 1  offset k in the packet
    "[x + {:04X}]",         # 2  offset k + x in the packet 
    "M[{:04X}]",            # 3  offset k in M
    "#{:04X}",              # 4  k literal
    "4*([{:04X}]&0xf)",     # 5  Lower nibble * 4 at byte offset k in the packet ???
    "{:04X}",               # 6  Label
    "#{:04X} {} {} ",       # 7  #k, jt, jf
    "x/%x {} {}",           # 8  x, jt, jf
    "#{:04X} {}",           # 9  #k, jt
    "x/%x {}",              # 10 x, jt
    "a/%a",                 # 11 accumulator
    "{:04X}"                # 12 extensions
]

def resolve_addr(values): pass

def resolve_label(values, compiler_state): pass

SIZE_MODS = [None, "b", "h", None, ""]

NEXT_FRAG = "__next_frag"

class AbstractCode(dict):
    '''Generic code class (bpf, instructions to flower, instructions
    to hardware, etc.
    '''
    def __init__(self, code="", reg="", size=4, mode=None, label=None):
        self.code = code + reg
        self.code += SIZE_MODS[size]
        self.mode = mode
        self.values = []
        self.label = label
        self.loc = COMPILER_STATE.get_loc()

    def __repr__(self):

        res = "\t"
        if self.label is not None:
            res = "{}:\t".format(self.label)

        res += self.code

        if self.mode is not None:
            res += "\t" + FORMATS[self.mode].format(*self.values) 
        return res

    def check_mode(self, mode, mask=None):
        '''Verify mode'''
        if not mode in mask:
            raise TypeError("Invalid Addressing mode {} not {} in ".format(mode, mask))

    def set_values(self, values):
        '''Values setter'''
    
        if isinstance(values, list):
            self.values = values
        else:
            self.values.append(values)

    def resolve_frag_refs(self, label):
        '''Resolve jump/load/etc refs'''
        pass

    def get_code(self):
        "Return compiled code"
        return self.code

    def get_loc(self):
        "Return loc"
        return self.loc

class Jump(AbstractCode):
    def init(self, code="", reg="", size=4, mode=None, label=None):
        super().__init__(code, reg, size, mode, label)

    def resolve_frag_refs(self, label):
        '''Resolve jump to next frag references'''
        for index in range(0, len(self.values)):
            if self.values[index] == NEXT_FRAG:
                self.values[index] = label 

class LD(AbstractCode):
    # Load into a register
    def __init__(self, values, reg="", size=4, mode=None, label=None):
        if reg == "x":
            self.check_mode(mode, [3, 4, 5, 12])
        else:
            self.check_mode(mode, [1, 2, 3, 4, 12])
        super().__init__(code="ld", reg=reg, size=size, mode=mode, label=label)
        self.set_values(values)

class ST(AbstractCode):
    def __init__(self, values, reg="", size=4, mode=0, label=None):
        super().__init__(code="st", reg=reg, size=size, mode=mode, label=label)
        self.set_values(values)

class JMP(Jump):
    def __init__(self, values, label=None):
        super().__init__(code="jmp", mode=6, label=label)
        self.set_values(values)

class JA(Jump):
    def __init__(self, values, label=None):
        super().__init__(code="ja", mode=6, label=label)
        self.set_values(values)

class CondJump(Jump):
    def __init__(self, values, code="jeq", mode=None, label=None):
        if code in ["jeq", "jgt", "jge", "jset"]:
            self.check_mode(mode, [7, 8, 9, 10])
        else:
            self.check_mode(mode, [9, 10])
        super().__init__(code=code, mode=mode, label=label)
        self.set_values(values)
        
class JEQ(CondJump):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="jeq", mode=mode, label=label)
        
class JNEQ(CondJump):
    def __init__(self, values, mode=None, label=None):
        super().__init__(vlues, code="jneq", mode=mode, label=label)

class JNE(CondJump):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="jne", mode=mode, label=label)

class JLT(CondJump):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="jlt", mode=mode, label=label)

class JLE(CondJump):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="jlt", mode=mode, label=label)

class JGT(CondJump):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="jgt", mode=mode, label=label)

class JGE(CondJump):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="jge", mode=mode, label=label)

class JSET(CondJump):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="jset", mode=mode, label=label)

class Arithmetics(AbstractCode):
    def __init__(self, values, code=None, mode=None, label=None):
        self.check_mode(mode, [0, 4])
        super().__init__(code=code, mode=mode, label=label)
        self.set_values(values)

class ADD(Arithmetics):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="add", mode=mode, label=label)

class SUB(Arithmetics):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="sub", mode=mode, label=label)

class MUL(Arithmetics):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="mul", mode=mode, label=label)

class DIV(Arithmetics):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="div", mode=mode, label=label)

class MOD(Arithmetics):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="mod", mode=mode, label=label)

class AND(Arithmetics):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="and", mode=mode, label=label)

class OR(Arithmetics):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="or", mode=mode, label=label)

class XOR(Arithmetics):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="xor", mode=mode, label=label)

class LSH(Arithmetics):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="lsh", mode=mode, label=label)

class RSH(Arithmetics):
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="rsh", mode=mode, label=label)

class NEG(AbstractCode):
    def __init__(self, label=None):
        super().__init__(None, code="neg", label=label)

class TAX(AbstractCode):
    def __init__(self, label=None):
        super().__init__(None, code="tax", label=label)

class TXA(AbstractCode):
    def __init__(self, label=None):
        super().__init__(None, code="txa", label=label)

class RET(AbstractCode):
    def __init__(self, values, mode=4, label=None):
        self.check_mode(mode, [4, 11])
        super().__init__(code="ret", mode=mode, label=label)
        self.set_values(values)

class Match(AbstractCode):
    '''Class describing a single filter match entry
    args: match_obj from parsing and match_location - 
    offset into the packet
    '''
    def __init__(self, match_obj, match_loc):
        self.match_obj = match_obj
        self.match_loc = match_loc
        self.code = []

    def __repr__(self):
        result = ""
        for item in self.code:
            result += "{}\n".format(item)
        return result

    def resolve_frag_refs(self, label):
        '''Resolve references to "jump to next frag"'''
        for insn in self.code:
            insn.resolve_frag_refs(label)

    def get_code(self):
        return self.code

V4_NET_REGEXP = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})")

class MatchIPv4(Match):
    '''IPv4 matcher. '''
    def __init__(self, match_obj, match_off=ETHER["size"], location=None):
        addr = V4_NET_REGEXP.match(match_obj[OBJ])
        if location is None:
            for qual in match_obj[QUALS]:
                location = match_off + IP.get(qual)
                if location is not None:
                    break
        if location is None:
            raise ValueError("Invalid address type specifier")
        super().__init__(match_obj, location)

        self.code.append(
            LD(self.match_loc, size=4, mode=1)
        )
        if addr is not None:
            netmask = 0xffffffff ^ (0xffffffff >> int(addr.group(2)))
            self.code.append(AND(netmask, mode=4))
            self.code.append(JEQ([IPv4toWord(addr.group(1)), NEXT_FRAG], mode=9))
        else:
            self.code.append(JEQ([IPv4toWord(match_obj[OBJ]), NEXT_FRAG], mode=9))
        self.code.append(RET(0, mode=4))

class MatchL2Proto(Match):
    def __init__(self, l2proto, offset=ETHER["proto"]):
        super().__init__(l2proto, offset)
        self.code.extend([
            LD(self.match_loc, size=4, mode=1),
            JEQ([ETH_PROTOS[l2proto], NEXT_FRAG], mode=9),
            RET(0, mode=4)
        ])

class MatchL3Proto(Match):
    def __init__(self, l3proto, offset=(IP["proto"] + ETHER["size"])):
        super().__init__(l3proto, offset)
        self.code.extend([
            LD(self.match_loc, size=1, mode=1),
            JEQ([IP_PROTOS[l3proto], NEXT_FRAG], mode=9),
            RET(0, mode=4)
        ])

class AbstractProgram():
    def __init__(self, frags=[], label=None):
        self.label = None
        self.frags = frags
        self.frag_refs_resolved = False

    def get_code(self):
        compiled = []
        for frag in frags:
            compiled.extend(frag.get_code())
        return compiled

    def resolve_frag_refs(self, old_loc_label=None):
        '''First pass in resolving references - insert
           internal labels to next code fragment where needed'''
        if self.frag_refs_resolved:
            return

        for index in range(len(self.frags) - 1, 0 , -1):
            frag = self.frags[index]
            loc_label = "__frag__{}".format(frag.get_code()[0].get_loc())
            if isinstance(frag, AbstractProgram):
                old_loc_label = frag.resolve_frag_refs(loc_label)
            else:
                for insn in frag.get_code():
                    insn.resolve_frag_refs(old_loc_label)
                old_loc_label = frag.get_code()[0].get_loc()
        self.frag_refs_resolved = True

    def __repr__(self):
        '''Representation'''
        res = ""
        for frag in self.frags:
            res += "{}".format(frag)
        return res

class ProgIP(AbstractProgram):
    def __init__(self):
        super().__init__(frags=[MatchL2Proto("ip"), MatchL3Proto("ip")])

class ProgIPv4(AbstractProgram):
    def __init__(self, match_obj, offset=None, location=None):
        if offset is None:
            super().__init__(frags=[ProgIP(), MatchIPv4(match_obj, location=location)])
        else:
            super().__init__(frags=[ProgIP(), MatchIPv4(match_obj, offset, location)])
            
