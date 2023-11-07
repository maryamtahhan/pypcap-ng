''' Pure python implementation of the pcap language parser.
Compiler backends.
'''


#
# Copyright (c) 2023 Red Hat, Inc., Anton Ivanov <anivanov@redhat.com>
# Copyright (c) 2023 Cambridge Greys Ltd <anton.ivanov@cambridgegreys.com>
#

from struct import Struct
import re
from header_constants import ETHER, IP, ETH_PROTOS, IP_PROTOS



IPV4_REGEXP = re.compile("(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")

class CompilerState():
    '''Compiler state for use in label generation
       additional L2 offsets.
       TODO: optimization information.
    '''
    def __init__(self):
        self.loc = 0
        self.extra_offset = 0

    def get_loc(self):
        '''Instruction ID'''
        self.loc += 1
        return self.loc

    def get_offset(self):
        '''Additional packet offset where applicable'''
        return self.extra_offset

    def add_offset(self, arg):
        '''Add extra offset'''
        self.extra_offset += arg


# Global compiler state

COMPILER_STATE = CompilerState()

def IPv4toWord(ipv4):
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

class AbstractCode(dict):
    '''Generic code class (bpf, instructions to flower, instructions
    to hardware, etc.
    '''
    def __init__(self, label=None):
        self.values = []
        if label is not None:
            if isinstance(label, list):
                self.labels = set(label)
            else:
                self.labels = set([label])
        else:
            self.labels = set()
        self.loc = COMPILER_STATE.get_loc()

    def has_label(self, label):
        '''Check if instruction has a label'''
        return label in self.labels

    def add_label(self, label):
        '''Add a label'''
        self.labels = self.labels | set([label])

    def replace_label(self, label, newlabel):
        '''Replace a label'''
        self.labels = self.labels ^ set([label]) | set([newlabel])

    def replace_value(self, value, newvalue):
        '''Replace a value'''
        for index in range(0, len(self.values)):
            if self.values[index] == value:
                self.values[index] = newvalue
                break

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



class CBPFCode(AbstractCode):
    '''BPF variant of code generation'''
    def __init__(self, code="", reg="", size=4, mode=None, label=None):
        super().__init__(label=label)
        self.code = code + reg
        self.code += SIZE_MODS[size]
        self.mode = mode

    def __repr__(self):
        '''Printable form of BPF instructions'''
        res = ""
        for label in self.labels:
            res += "{}:\n".format(label)

        res += "\t" + self.code

        if self.mode is not None:
            res += "\t" + FORMATS[self.mode].format(*self.values) 
        return res

    def check_mode(self, mode, mask=None):
        '''Verify mode'''
        if not mode in mask:
            raise TypeError("Invalid Addressing mode {} not {} in ".format(mode, mask))

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
    def __init__(self, code=None, values=None, mode=6, label=None):
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
    def __init__(self, values, code="jeq", mode=None, label=None):
        if code in ["jeq", "jgt", "jge", "jset"]:
            self.check_mode(mode, [7, 8, 9, 10])
        else:
            self.check_mode(mode, [9, 10])
        super().__init__(code=code, mode=mode, label=label)
        self.set_values(values)

class JEQ(CondJump):
    '''Jump on equal'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="jeq", mode=mode, label=label)
        
class JNEQ(CondJump):
    '''Jump on not equal'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(vlues, code="jneq", mode=mode, label=label)

class JNE(CondJump):
    '''Jump on not equal'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="jne", mode=mode, label=label)

class JLT(CondJump):
    '''Jump on less then'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="jlt", mode=mode, label=label)

class JLE(CondJump):
    '''Jump on less or equal'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="jlt", mode=mode, label=label)

class JGT(CondJump):
    '''Jump on greater'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="jgt", mode=mode, label=label)

class JGE(CondJump):
    '''Jump on greater or equal'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="jge", mode=mode, label=label)

class JSET(CondJump):
    '''Jump on a set bit'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="jset", mode=mode, label=label)

class Arithmetics(CBPFCode):
    '''Generic arithmetic instruction'''
    def __init__(self, values, code=None, mode=None, label=None):
        self.check_mode(mode, [0, 4])
        super().__init__(code=code, mode=mode, label=label)
        self.set_values(values)

class ADD(Arithmetics):
    '''ADD instruction'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="add", mode=mode, label=label)

class SUB(Arithmetics):
    '''SUB instruction'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="sub", mode=mode, label=label)

class MUL(Arithmetics):
    '''MUL instruction'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="mul", mode=mode, label=label)

class DIV(Arithmetics):
    '''DIV instruction'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="div", mode=mode, label=label)

class MOD(Arithmetics):
    '''MOD instruction'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="mod", mode=mode, label=label)

class AND(Arithmetics):
    '''Arithmetic AND instruction'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="and", mode=mode, label=label)

class OR(Arithmetics):
    '''Arithmetic OR instruction'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="or", mode=mode, label=label)

class XOR(Arithmetics):
    '''Arithmetic XOR instruction'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="xor", mode=mode, label=label)

class LSH(Arithmetics):
    '''LSH instruction'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="lsh", mode=mode, label=label)

class RSH(Arithmetics):
    '''RSH instruction'''
    def __init__(self, values, mode=None, label=None):
        super().__init__(values, code="rsh", mode=mode, label=label)

class NEG(CBPFCode):
    '''NEG instruction'''
    def __init__(self, label=None):
        super().__init__(None, code="neg", label=label)

class TAX(CBPFCode):
    '''Transfer A to X'''
    def __init__(self, label=None):
        super().__init__(None, code="tax", label=label)

class TXA(CBPFCode):
    '''Transfer X to A'''
    def __init__(self, label=None):
        super().__init__(None, code="txa", label=label)

class RET(CBPFCode):
    '''RET with result.
       cBPF convention is 0 for failure and non
       negative packet "size" for success
    '''
    def __init__(self, values, mode=4, label=None):
        self.check_mode(mode, [4, 11])
        super().__init__(code="ret", mode=mode, label=label)
        self.set_values(values)


#### Matchers


class Match(AbstractCode):
    '''Class describing a single filter match entry
       args: match_obj from parsing and match_location - 
       offset into the packet
    '''
    def __init__(self, match_obj, match_loc, jt=NEXT_MATCH,
                 jf=FAIL, parent=None):

        super().__init__()
        self.jt = jt
        self.jf = jf
        self.code = []
        self.marked = False
        self.compiled = False
        self.start_label = "__match__start_{}".format(self.loc)
        self.end_label = "__match__end_{}".format(self.loc)
        self.match_obj = match_obj
        self.match_loc = match_loc
        self.parent = parent
        self.quals = set()

    def __repr__(self):
        '''Printable form - just print the instructions'''
        result = ""
        for item in self.code:
            result += "{}\n".format(item)
        return result

    def resolve_refs(self, old_label, new_label):
        '''Resolve references to "jump to next frag"'''
        for insn in self.code:
            insn.resolve_refs(old_label, new_label)

    def get_code(self):
        '''Return the code corresponding to this match expression'''
        # If there is no label marking this match expression, add it
        return self.code

    def replace_value(self, oldvalue, newvalue, index=None):
        '''Replace values in match insns'''
        for insn in self.code:
            insn.replace_value(oldvalue, newvalue)

    def set_jt(self, jt, last_frag=False):
        '''Set jump target if this match is True'''
        self.jt = jt
        
    def set_jf(self, jf, last_frag=False):
        '''Set jump target if this match is False'''
        self.jf = jf

    def set_parent(self):
        pass

    def add_quals(self, quals):
        self.quals = self.quals | quals

    def compile(self):
        '''Compile the code'''
        self.compiled = True
        self.update_labels()

    def update_labels(self):
        if self.compiled:
            self.code[0].add_label(self.start_label)
            self.code[-1].add_label(self.end_label)

    def get_end_label(self):
        return self.end_label

    def get_start_label(self):
        return self.start_label

    def get_next_match(self):
        if self.parent is not None:
            return parent.get_next_match(self)

V4_NET_REGEXP = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})")

class MatchIPv4(Match):
    '''IPv4 address matcher.'''
    def __init__(self, match_obj, jt=NEXT_MATCH, jf=FAIL, match_off=ETHER["size"]):

        super().__init__(match_obj, match_off, jt, jf)

    def compile(self):
        '''Generate the actual code for the match'''

        addr = V4_NET_REGEXP.match(self.match_obj)
        location = None
        for qual in self.quals:
            try:
                location = self.match_loc + IP[qual]
            except KeyError:
                pass
            if location is not None:
                break
        if location is None:
            raise ValueError("Invalid address type specifier")
        self.code.append(
            LD(location, size=4, mode=1)
        )
        if addr is not None:
            netmask = 0xffffffff ^ (0xffffffff >> int(addr.group(2)))
            self.code.append(AND(netmask, mode=4))
            self.code.append(JEQ([IPv4toWord(addr.group(1)), self.jt, self.jf], mode=7))
        else:
            self.code.append(JEQ([IPv4toWord(self.match_obj), self.jt, self.jf], mode=7))
        super().compile()

class MatchL2Proto(Match):
    '''Layer 2 protocol matcher'''
    def __init__(self, l2proto, jt=NEXT_MATCH, jf=FAIL, offset=ETHER["proto"]):
        super().__init__(l2proto, offset, jt, jf)
        self.l2proto = ETH_PROTOS[l2proto]

    def compile(self):
        self.code.extend([
            LD(self.match_loc, size=2, mode=1),
            JEQ([self.l2proto, self.jt, self.jf], mode=7),
        ])
        super().compile()

class Match8021Q(MatchL2Proto):
    '''Vlan matcher'''
    def __init__(self, vlan, jt=NEXT_MATCH, jf=FAIL, offset=ETHER["proto"]):
        super().__init__("qtag", jt=jt, jf=jf, offset=offset)
        self.vlan = vlan
        self.offset = offset

    def compile(self):
        self.code.extend([
            LD(self.offset + 2, size=2, mode=1),
            AND(0x3F, mode=4),
            JEQ([self.vlan, self.jt, self.jf], mode=7)
        ])
        super().compile()

class MatchL3Proto(Match):
    '''Layer 3 protocol matcher'''
    def __init__(self, l3proto, jt=NEXT_MATCH, jf=FAIL, offset=(IP["proto"] + ETHER["size"])):
        super().__init__(l3proto, offset, jt, jf)
        self.l3proto = IP_PROTOS[l3proto]

    def compile(self):
        self.code.extend([
            LD(self.match_loc, size=1, mode=1),
            JEQ([self.l3proto, self.jt, self.jf], mode=7),
        ])
        super().compile()

class Fail(Match):
    '''Return with a fail code. Always the last match/instruction.'''
    def __init__(self):
        super().__init__(None, None)

    def compile(self):
        self.code.extend([RET(0, label=[LAST_INSN, FAIL])])
        super().compile()
        
class Success(Match):
    '''Return with a success code'''
    def __init__(self):
        super().__init__(None, None)
    
    def compile(self):
        self.code.extend([RET(0xFFFF, label=SUCCESS)])
        super().compile()
        

class AbstractProgram():
    '''Chunk of code - fragments can be matchers or other programs'''
    def __init__(self, jt=NEXT_MATCH, jf=FAIL, parent=None, frags=[], label=None):
        self.label = None
        if not isinstance(frags, list):
            frags = [frags]
        self.frags = frags
        self.frag_refs_resolved = False
        self.compiled = False
        self.jt = jt
        self.jf = jf
        self.parent = parent
        self.quals = set()
        self.set_parent()

    def __repr__(self):
        '''Program (fragment) representation'''
        res = ""
        for frag in self.frags:
            res += "{}".format(frag)
        return res

    def get_code(self):
        '''Resulting code dump'''
        code = []
        for frag in self.frags:
            code.extend(frag.get_code())
        return code

    def add_quals(self, quals):
        '''Resulting code dump'''
        for frag in self.frags:
            frag.add_quals(quals)

    def compile(self):
        if not self.compiled:
            for frag in self.frags:
                frag.compile()
            self.compiled = True

    def set_parent(self):
        for frag in self.frags:
            frag.parent = self
            frag.set_parent()

    def replace_value(self, old, new, index=None):
        if index is not None:
            self.frags[index].replace_value(old, new, index=index)
        else:
            for frag in frags:
                frag.replace_value(old, new)

class CBPFProgram(AbstractProgram):
    '''cBPF variant of AbstractProgram'''
    def __init__(self, jt=NEXT_MATCH, jf=FAIL, frags=[], label=None, update_labels=False):
        super().__init__(jt=jt, jf=jf, frags=frags, label=label)

        if update_labels:
            if jt is not None:
                self.set_jt(jt)
            if jf is not None:
                self.set_jf(jf)

    def set_jt(self, jt, last_frag=False):
        self.jt = jt
        if last_frag:
            self.frags[-1].set_jt(jt, last_frag=last_frag)
        else:
            for frag in self.frags:
                frag.set_jt(jt)
        
    def set_jf(self, jf, last_frag=False):
        self.jf = jf
        if last_frag:
            self.frags[-1].set_jt(jt, last_frag=last_frag)
        else:
            for frag in self.frags:
                frag.set_jf(jf)

    def get_start_label(self):
        return self.frags[0].get_start_label()

    def get_end_label(self):
        return self.frags[0].get_end_label()

    def get_next_match(self, item):
        if self.frags[-1] == item: 
            return self.parent.get_next_match(self)
        return self.frags[self.frags.index(item) + 1].get_start_label()

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
            if self.parent is not None:
                item.resolve_refs(PARENT_NEXT, self.parent.get_next_match())
            for label in item.labels:
                if "__match__start" in label:
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

# These are way too cBPF specific to try to make them into generic instances

class ProgIP(CBPFProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self):
        super().__init__(frags=[MatchL2Proto("ip")])

class ProgIPv4(CBPFProgram):
    '''Basic match on v4 address or network.
    '''
    def __init__(self, match_obj, offset=None):
        if offset is None:
            super().__init__(frags=[ProgIP(), MatchIPv4(match_obj)])
        else:
            super().__init__(frags=[ProgIP(), MatchIPv4(match_obj, offset=offset)])

class ProgNOT(CBPFProgram):
    '''Negate the result of all frags.
    '''
    def __init__(self, frags):
        # swap jt and jf

        super().__init__(frags=frags)
        self.set_jt(FAIL, last_frag=True)
        self.set_jf(SUCCESS)


class ProgOR(CBPFProgram):
    '''Perform logical OR on left and right frag(s)
    '''
    def __init__(self, left, right):
        right = CBPFProgram(frags=right)
        left = CBPFProgram(frags=left, jt=NEXT_MATCH, jf=right.get_start_label(), update_labels=True)
        left.set_jt(SUCCESS, last_frag=True)

        super().__init__(frags=[left, right])
        

class ProgAND(CBPFProgram):
    '''Perform logical AND on left and right frag(s)
    '''
    def __init__(self, left, right):

        right = CBPFProgram(frags=right)
        left = CBPFProgram(frags=left)
        super().__init__(frags=[left, right])


def finalize(prog):
    '''Add success and failure return instructions to the end'''
    return CBPFProgram(frags=[prog, Success(), Fail()], jt=NEXT_MATCH, jf=FAIL)
