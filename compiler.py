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
    "[0x{:04X}]",             # 1  offset k in the packet
    "[x + 0x{:04X}]",         # 2  offset k + x in the packet 
    "M[0x{:04X}]",            # 3  offset k in M
    "#0x{:04X}",              # 4  k literal
    "4*([0x{:04X}]&0xf)",     # 5  Lower nibble * 4 at byte offset k in the packet ???
    "0x{:04X}",               # 6  Label
    "#0x{:04X} jt {} jf {} ",       # 7  #k, jt, jf
    "x/%x jt {} jf {}",           # 8  x, jt, jf
    "#0x{:04X} jt {}",           # 9  #k, jt
    "x/%x jt {}",              # 10 x, jt
    "a/%a",                 # 11 accumulator
    "0x{:04X}"                # 12 extensions
]

def resolve_addr(values): pass

def resolve_label(values, compiler_state): pass

SIZE_MODS = [None, "b", "h", None, ""]

NEXT_MATCH = "__next_match"
LAST_INSN = "__last_insn"
SUCCESS = "__success"
FAIL = "__fail"

class AbstractCode(dict):
    '''Generic code class (bpf, instructions to flower, instructions
    to hardware, etc.
    '''
    def __init__(self, code="", reg="", size=4, mode=None, label=None):
        self.code = code + reg
        self.code += SIZE_MODS[size]
        self.mode = mode
        self.values = []
        self.labels = []
        if label is not None:
            if isinstance(label, list):
                self.labels.extend(label)
            else:
                self.labels = [label]
        self.loc = COMPILER_STATE.get_loc()

    def __repr__(self):

        res = ""
        for label in self.labels:
            res += "{}:\n".format(label)

        res += "\t" + self.code

        if self.mode is not None:
            res += "\t" + FORMATS[self.mode].format(*self.values) 
        return res

    def has_label(self, label):
        return label in self.labels

    def add_label(self, label):
        if not label in self.labels:
            self.labels.append(label)

    def replace_label(self, label, newlabel):
        for index in range(0, len(self.labels)):
            if label == self.labels[index]:
                self.labels[index] = label
                break

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

    def resolve_refs(self, old_label, new_label):
        '''Resolve jump/load/etc refs'''
        pass

    def get_code(self):
        "Return compiled code"
        return self.code

    def get_loc(self):
        "Return loc"
        return self.loc


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

class Jump(AbstractCode):
    def __init__(self, code=None, values=None, mode=6, label=None):
        super().__init__(code=code, mode=mode, label=label)
        self.set_values(values)

    def resolve_refs(self, old_label, new_label):
        for index in range(0, len(self.values)):
            if self.values[index] == old_label:
                self.values[index] = new_label

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
    def __init__(self, match_obj, match_loc, jf=None, jt=None):
        self.match_obj = match_obj
        self.match_loc = match_loc
        self.jt = jt
        self.jf = jf
        self.code = []
        self.marked = False

    def __repr__(self):
        result = ""
        for item in self.code:
            result += "{}\n".format(item)
        return result

    def resolve_refs(self, old_label, new_label):
        '''Resolve references to "jump to next frag"'''
        for insn in self.code:
            insn.resolve_refs(old_label, new_label)

    def get_code(self):
        self.code[0].add_label("__match__{}".format(self.code[0].get_loc()))
        return self.code

V4_NET_REGEXP = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})")

class MatchIPv4(Match):
    '''IPv4 matcher. '''
    def __init__(self, match_obj, jt=None, jf=None, match_off=ETHER["size"], location=None):
        addr = V4_NET_REGEXP.match(match_obj[OBJ])
        if location is None:
            for qual in match_obj[QUALS]:
                location = match_off + IP.get(qual)
                if location is not None:
                    break
        if location is None:
            raise ValueError("Invalid address type specifier")
        super().__init__(match_obj, location, jt, jf)

        self.code.append(
            LD(self.match_loc, size=4, mode=1)
        )
        if addr is not None:
            netmask = 0xffffffff ^ (0xffffffff >> int(addr.group(2)))
            self.code.append(AND(netmask, mode=4))
            self.code.append(JEQ([IPv4toWord(addr.group(1)), jt, jf], mode=7))
        else:
            self.code.append(JEQ([IPv4toWord(match_obj[OBJ]), jt, jf], mode=7))

class MatchL2Proto(Match):
    def __init__(self, l2proto, jt=None, jf=None, offset=ETHER["proto"]):
        super().__init__(l2proto, offset, jt, jf)
        self.code.extend([
            LD(self.match_loc, size=4, mode=1),
            JEQ([ETH_PROTOS[l2proto], jt, jf], mode=7),
        ])

class MatchL3Proto(Match):
    def __init__(self, l3proto, jt=None, jf=None, offset=(IP["proto"] + ETHER["size"])):
        super().__init__(l3proto, offset, jt, jf)
        self.code.extend([
            LD(self.match_loc, size=1, mode=1),
            JEQ([IP_PROTOS[l3proto], jt, jf], mode=7),
        ])

class Fail(Match):
    def __init__(self):
        super().__init__(None, None)
        self.code.extend([RET(0, label=[LAST_INSN, FAIL])])
        
class Success(Match):
    def __init__(self):
        super().__init__(None, None)
        self.code.extend([RET(0xFFFF, label=SUCCESS)])
        

class AbstractProgram():
    def __init__(self, jt=None, jf=None, frags=[], label=None):
        self.label = None
        self.frags = frags
        self.frag_refs_resolved = False

    def get_code(self):
        compiled = []
        for frag in self.frags:
            compiled.extend(frag.get_code())
        return compiled

    def resolve_frag_refs(self, old_loc_label=None):
        '''First pass in resolving references - insert
           internal labels to next code fragment where needed'''

        code = self.get_code()

        if not code[-1].has_label(LAST_INSN):
            raise ValueError("Invalid Program - no last instruction marker")
        next_frag = LAST_INSN
        for index in range(len(code) -1 , -1, -1):
            item = code[index]
            item.resolve_refs(NEXT_MATCH, next_frag)
            for label in item.labels:
                if "__match__" in label:
                    next_frag = label

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
                code[index].labels = []
                

    def __repr__(self):
        '''Representation'''
        res = ""
        for frag in self.frags:
            res += "{}".format(frag)
        return res

class ProgIP(AbstractProgram):
    def __init__(self, jt=None, jf=None):
        super().__init__(jt=jt, jf=jf, frags=[MatchL2Proto("ip", jt=jt, jf=jf)])

class ProgIPv4(AbstractProgram):
    def __init__(self, match_obj, jt=None, jf=None, offset=None, location=None):
        if offset is None:
            super().__init__(frags=[ProgIP(jt=jt, jf=jf), MatchIPv4(match_obj, jt=jt, jf=jf, location=location), Success(), Fail()])
        else:
            super().__init__(frags=[ProgIP(jt=jt, jf=jf), MatchIPv4(match_obj, jt=jt, jf=jf, offset=offset, location=location), Success(), Fail()])
