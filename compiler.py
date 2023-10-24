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

# SYMBOLIC REGISTER NAMES
RET = 'RET' # AX in (c|e)BPF

INS_PACK = Struct("=HBBI")

IPV4_REGEXP = re.compile("(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")

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

SIZE_MODS = {4 : "", 2 : "h", 1 : "b"}
FORMATS = [
    "x/%x",             # register x
    "[{:04X}]",             # offset k in the packet
    "[x + {:04X}]",         # offset k + x in the packet 
    "M[{:04X}]",             # offset k in M
    "#{:04X}",              # k literal
    "4*([{:04X}]&0xf)",     # Lower nibble * 4 at byte offset k in the packet ???
    "{:04X}",               # Label
    "#{:04X} {} {} ",       # #k, jt, jf
    "x/%x {} {}",       # x, jt, jf
    "#{:04X} {}",           # #k, jt
    "x/%x {}",          # x, jt
    "a/%a",             # accumulator
    "{:04X}"                # extensions
]

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

    def __repr__(self):
        res = "\t"
        if self.label is not None:
            res = "{}:\t".format(self.label)
        
    
            
        if self.mode is not None:
            res += self.code + "\t" + FORMATS[self.mode].format(*self.values) 
        else:
            res += self.code
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

    def resolve_references(self):
        '''Resolve jump/load/etc refs'''
        pass
        

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

class JMP(AbstractCode):
    def __init__(self, values, label=None):
        super().__init__(code="jmp", mode=6, label=label)
        self.set_values(values)
        
class JA(AbstractCode):
    def __init__(self, values, label=None):
        super().__init__(code="ja", mode=6, label=label)
        self.set_values(values)

class CondJump(AbstractCode):
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

V4_NET_REGEXP = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})")


class MatchIPv4(Match):
    '''IPv4 matcher'''
    def __init__(self, match_obj, match_loc):
        super().__init__(match_obj, match_loc)
        self.code.append(
            LD(self.match_loc, size=4, mode=3)
        )
        addr = V4_NET_REGEXP.match(match_obj[OBJ])
        if addr is not None:
            netmask = 0xffffffff ^ (0xffffffff >> int(addr.group(2)))
            self.code.append(AND(netmask, mode=4))
            self.code.append(JEQ([IPv4toWord(addr.group(1)), "next"], mode=9))
        else:
            self.code.append(JEQ([IPv4toWord(match_obj[OBJ]), "next"], mode=9))
        self.code.append(RET(0, mode=4))

class MatchL2Proto(Match):
    def __init__(self, l2proto, offset=12):
        super()._init(l2proto, offset)
        self.code.append(
            LD(self.match_loc, size=4, mode=3),
            JEQ([l2proto], "next" ,mode=9),
            RET(0, mode=4)
        )

class MatchSRCv4(MatchIPv4):
    '''IPv4 SRC Matcher'''
    def __init__(self, match_obj, l2_hdr_size):
        super_init(self, match_obj, l2_hdr_size + 12)

class MatchDSTv4(MatchIPv4):
    '''IPv4 DST Matcher'''
    def __init__(self, match_obj, l2_hdr_size):
        super_init(self, match_obj, l2_hdr_size + 16)
