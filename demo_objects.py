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
from code_objects import AbstractCode, AbstractHelper, NEXT_MATCH, FAIL, SUCCESS, LAST_INSN, Immediate, AbortBranch


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

class DEMOCompilerState():
    '''DEMO Specific compiler state'''

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


V4_NET_REGEXP = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})")

class DEMOHelper(AbstractHelper):
    '''cBPF variant of AbstractHelper'''
    def __init__(self, pcap_obj):
        super().__init__(pcap_obj)
        self.helper_id = "simulated offload"

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
        self.pcap_obj.add_code(code, self.helper_id)

    def add_offset_code(self, code):
        '''Invoke pcap obj add_code'''
        self.pcap_obj.add_offset_code(code, self.helper_id)

# These are way too cBPF specific to try to make them into generic instances

class DEMOCode(AbstractCode):
    def __init__(self, match_object):
        super().__init__()
        self.match_object = match_object
        

    def __str__(self):
        '''Same as repr'''
        return self.__repr__()

    def __repr__(self):
        '''Printable form of Demo Offload instructions'''

        res = ""

        if self.match_object is not None:

            res = ":\n".join(self.labels)
            res += "\t direct offload of:" + self.match_object

        return res

class DEMOProgIP(DEMOHelper):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def compile(self, compiler_state=None):
        '''Compile offset past IP Headers'''
        super().compile(compiler_state)
        self.add_code([DEMOCode("protocol = ip")])
        raise AbortBranch("branch offloaded")
    
class DEMONoP(DEMOHelper):
    '''NOP
    '''

def dispatcher(obj):
    '''Return the correct code helper'''
    try:
        return getattr(sys.modules[__name__], f"DEMO{obj.__class__.__name__}")(obj)
    except AttributeError:
        return DEMONoP(obj)
