''' Pure python implementation of the pcap language parser.
Compiler backends - U32.
'''


#
# Copyright (c) 2023 Red Hat, Inc., Anton Ivanov <anivanov@redhat.com>
# Copyright (c) 2023 Cambridge Greys Ltd <anton.ivanov@cambridgegreys.com>
#

import sys
import re
import ipaddress
from header_constants import ETHER, IP, IP6, ETH_PROTOS
from code_objects import AbstractCode, AbstractHelper


# Some of the names are predefined. They are instruction names. We
# should not change them.
#pylint: disable=line-too-long, invalid-name, consider-using-f-string


IPV4_REGEXP = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")



SIZE_MODS = [None, "u8", "u16", None, "u32"]

# U32 instruction as described in the literature is not an instruction
# when using our abstractions. It is a mini-program which consists f
# LD (absolute or index), SHL or SHR, AND and a comparison - a total
# of four instructions

LD_OP = 0
SH_OP = 1
AND_OP = 2
COMP_OP = 3

class U32Code(AbstractCode):
    '''U32 variant of code generation'''
    def __init__(self, master=False):
        super().__init__()
        self.master = master
        self.comp = []

    def obj_dump(self, counter):
        '''Dump bytecode'''
        if self.master:
            return f"{counter} {self}\n"
        return ""

    def __repr__(self):
        '''Same as repr'''
        return f"{self}"

    def __str__(self):
        '''Printable form of U32 instructions'''
        return ""

class U32LD(U32Code):
    '''U32 variant of LD subinstruction'''
    def __init__(self, location=0, size=4, index=False):
        super().__init__(master=True)
        self.location = location
        self.size = size
        self.index = index
        self.comp.append(self)

    def __str__(self):
        '''Printable form of U32 instructions'''

        ret = "{}".format(self.location)
        shift = (32 - self.size * 8) + self.comp[SH_OP].shift
        mask = ((1 << (self.size * 8)) - 1)

        if self.comp[SH_OP].shift < 0:
            mask = (mask << abs(self.comp[SH_OP].shift)) & self.comp[AND_OP].mask
        elif self.comp[SH_OP].shift > 0:
            mask = (mask >> self.comp[SH_OP].shift) & self.comp[AND_OP].mask
        else:
            mask = self.comp[AND_OP].mask & mask

        if shift < 0:
            ret += " << " + str(abs(shift))
        elif shift > 0:
            ret += " >> " + str(shift)

        try:
            if self.comp[COMP_OP].lower == self.comp[COMP_OP].upper:
                value = "{:04x}".format(self.comp[COMP_OP].lower)
            else:
                value = "{:04x}:{:04x}".format(self.comp[COMP_OP].lower,self.comp[COMP_OP].upper)

            return ret + f" 0x{mask:04x} = {value}"
        except IndexError:
            pass
        except AttributeError:
            classes = []
            for op in self.comp:
                classes.append(op.__class__.__name__)
            return f"Off by one {classes}"

        # no check - just offset (it is really a check 0-0xFFFF)

        return ret + f" 0x{mask:04x} @"



class U32SH(U32Code):
    '''U32 variant of SHL/SHR. SHL is represented using negative values'''
    def __init__(self, shift=0):
        super().__init__()
        self.shift = shift

class U32AND(U32Code):
    '''U32 variant of code generation'''
    def __init__(self, mask=0xFFFFFFFF):
        super().__init__()
        self.mask = mask

class U32Compare(U32Code):
    '''U32 variant of code generation'''
    def __init__(self, lower=0, upper=0xFFFFFFFF):
        super().__init__()
        self.lower = lower
        self.upper = upper

class U32LogicalAND(AbstractCode):
    '''U32 variant of code generation'''
    def __init__(self):
        super().__init__()

    def obj_dump(self, counter):
        '''Dump bytecode'''
        return f"{counter} {self}"

    def __str__(self):
        '''Same as repr'''
        return self.__repr__()

    def __repr__(self):
        '''Printable form of U32 instructions'''
        return "&&"

V4_NET_REGEXP = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})")

class U32Helper(AbstractHelper):
    '''U32 variant of AbstractHelper'''
    def __init__(self, pcap_obj):
        super().__init__(pcap_obj)
        self.helper_id = "u32"
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
        '''attribs getter'''
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

        if len(code) == 0:
            return


        last_ld = None
        to_add = True
        for insn in code:
            if isinstance(insn, U32LD):
                last_ld = insn
                to_add = len(last_ld.comp) == 1
            elif isinstance(insn, U32LogicalAND):
                pass
            else:
                if last_ld is not None and to_add:
                    last_ld.comp.append(insn)
        try:
            if isinstance(self.pcap_obj.get_code(self.helper_id)[-1], U32Compare) and \
                isinstance(code[0], U32LD):
                self.pcap_obj.add_code([U32LogicalAND()], self.helper_id)
        except IndexError:
            pass

        self.pcap_obj.add_code(code, self.helper_id)

    def add_offset_code(self, code):
        '''Invoke pcap obj add_code'''
        if len(code) == 0:
            return

        last_ld = None
        for insn in code:
            if isinstance(insn, U32LD):
                last_ld = insn
            elif isinstance(insn, (U32LogicalAND, U32Compare)):
                raise ValueError()
            else:
                if last_ld is not None:
                    last_ld.comp.append(insn)
        self.pcap_obj.add_offset_code(code, self.helper_id)


# These are way too cU32 specific to try to make them into generic instances

class U32AbstractProgram(U32Helper):
    '''Do nothing - attaches to a program which just calls subs.
    '''

class U32ProgSuccess(U32Helper):
    '''Success
    '''
    # NOP in U32. There is no "return a value like in BPF"

class U32ProgFail(U32Helper):
    '''Fail
    '''
    # NOP in U32. There is no "return a value like in BPF"


class U32ProgL2(U32Helper):
    '''Basic L2 Match
    '''

    def compile(self, compiler_state=None):

        super().compile(compiler_state)
        compiler_state.set_offset("L2", ETHER["size"])
        match = self.match_object
        if isinstance(self.match_object, str):
            match = ETH_PROTOS[self.match_object]

        self.add_code([
            U32LD(location=ETHER["proto"] + self.offset, size=2),
            U32SH(),
            U32AND(mask=0xFFFF),
            U32Compare(lower=match, upper=match)
        ])

class U32Prog8021Q(U32Helper):
    '''Vlan matcher'''
    def compile(self, compiler_state=None):

        super().compile(compiler_state)
        compiler_state.add_offset("L2T", 4)
        match = self.match_object
        self.add_code([
            U32LD(compiler_state.get_offset("L2") + 2 + self.offset, size=2),
            U32SH(),
            U32AND(mask=0xFFF),
            U32Compare(lower=match, upper=match)
        ])

    def compile_offsets(self, compiler_state=None):
        '''802.1q offset'''
        return compiler_state.get_offset(["L2", "L2T"])


PORT = {
    "src": 0,
    "dst": 2
}

class U32ProgL3(U32Helper):
    '''Layer 3 protocol matcher'''
    def compile(self, compiler_state=None):
        '''Compile the code'''

        super().compile(compiler_state)
        match = self.match_object
        self.add_code([
            U32LD(compiler_state.get_offset(["L2", "L2T"]) + IP["proto"] + self.offset, size=1),
            U32SH(),
            U32AND(mask=0xFF),
            U32Compare(lower=match, upper=match)
        ])

class U32ProgIP(U32Helper):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''

    def compile(self, compiler_state=None):
        '''We need to check IP version. As a side effect
           This also deals with references after an L2 trim.
        '''
        super().compile(compiler_state=None)

        ip_version = self.pcap_obj.ip_version
        self.add_code([
            U32LD(compiler_state.get_offset(["L2", "L2T"]) + self.offset, size=1),
            U32SH(shift=4),
            U32AND(mask=0xFF),
            U32Compare(lower=ip_version, upper=ip_version)
        ])

    def compile_offsets(self, compiler_state=None):
        '''Compile offset past IP Headers'''

        super().compile_offsets(compiler_state)

        if int(self.ip_version) == 4:
            self.add_offset_code([
                U32LD(compiler_state.get_offset(["L2", "L2T", "L3"]) + self.offset, size=1),
                U32SH(shift=-2),
                U32AND(mask=0x3C),
                # no compare!!!
            ])
        else:
            compiler_state.set_offset("L3", 40)

class U32ProgTCP(U32ProgL3):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''

    def compile_offsets(self, compiler_state=None):
        '''Compile offset past IP Headers'''
        super().compile_offsets(compiler_state)

        self.add_offset_code([
            U32LD(compiler_state.get_offset(["L2", "L2T"]) + 12 + self.offset, size=1),
            U32SH(shift=0),
            U32AND(mask=0xF0),
            # no compare!!!
        ])

class U32ProgPortRange(U32Helper):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def compile(self, compiler_state=None):
        '''Compile the code'''

        super().compile(compiler_state)

        try:
            left = self.attribs["loc"][0]
            try:
                right = self.attribs["loc"][1]
            except IndexError:
                right = left
            left.compile(compiler_state)
            right.compile(compiler_state)
        except KeyError:
            left = right = self.pcap_obj.frags[0]

        if left.result is None or right.result is None:
            raise ValueError("U32 does not allow dynamic offset computation")

        self.compile_offsets(compiler_state)

        # this should really come from compile_offsets
        self.add_code([
            U32LD(compiler_state.get_offset(["L2", "L2T", "L3"]) + self.offset, size=1),
            U32SH(shift=-2),
            U32AND(mask=0x3FC),
            # no compare!!!
        ])

        if "src" in self.pcap_obj.quals:
            self.add_code([
                U32LD(size=2),
                U32SH(shift=0),
                U32AND(mask=0xFFFF),
                U32Compare(lower=left.result, upper=right.result)
            ])
            if "dst" in self.pcap_obj.quals:
                self.add_code([U32AND()])

        if "dst" in self.pcap_obj.quals:
            self.add_code([
                U32LD(location=2, size=2),
                U32SH(shift=0),
                U32AND(mask=0xFFFF),
                U32Compare(lower=left.result, upper=right.result)
            ])

class U32ProgPort(U32ProgPortRange):
    '''Port (maps to Port Range)'''

class U32ProgIPv4(U32Helper):
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

        if isinstance(addr, ipaddress.IPv4Network):
            mask = int(addr.netmask)
            value = int(addr.network_address)
        else:
            mask = 0xFFFFFFFF
            value = int(addr)

        self.add_code([
            U32LD(location=location, size=4),
            U32SH(shift=0),
            U32AND(mask=mask),
            U32Compare(lower=value, upper=value)
        ])

class U32ProgIPv6(U32Helper):
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
            netmask = int(addr.netmask).to_bytes(16)
            address = int(addr.network_address).to_bytes(16)
        else:
            address = int(addr).to_bytes(16)
            netmask = bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff])
        for nibble in range(0,4):
            value = int.from_bytes(address[nibble*4:nibble*4 + 4])
            mask = int.from_bytes(netmask[nibble*4:nibble*4 + 4])
            self.add_code([
                U32LD(location=location + nibble * 4, size=4),
                U32SH(shift=0),
                U32AND(mask=mask),
                U32Compare(lower=value, upper=value)
            ])
            if nibble < 3:
                code.extend(U32LogicalAND())
        self.add_code(code)


class U32ProgNOT(U32Helper):
    '''Negate the result of all frags.
    '''
    def compile(self, compiler_state=None):
        '''Compile NOT - inverse true and false'''
        raise ValueError("NOT not supported in U32")


class U32ProgOR(U32Helper):
    '''Perform logical OR on left and right frag(s)
    '''
    def compile(self, compiler_state=None):
        '''Compile OR - inverse true and false'''
        raise ValueError("NOT not supported in U32")

class U32ProgAND(U32Helper):
    '''Perform logical AND on left and right frag(s)
    '''
    def compile(self, compiler_state=None):
        '''Compile AND'''

        self.left.compile(compiler_state)
        self.left.add_code([U32LogicalAND()], self.helper_id)
        self.right.compile(compiler_state)

#COMP_TABLE = {
#    "<" : JLT,
#    ">" : JGT,
#    "==" : JEQ,
#    "!=" : JNEQ,
#    ">=" : JGE,
#    "<=" : JLE
#}

class U32ProgOffset(U32Helper):
    '''Perform computation of offset to payload
    '''

    def compile(self, compiler_state=None):
        '''We compile offset code instead of the normal
           match logic.
        '''

        super().compile(compiler_state)
        self.pcap_obj.compile_offsets(compiler_state)

class U32ProgLoad(U32Helper):
    '''Load a value from packet address
    '''
    def compile(self, compiler_state=None):
        '''Compile arithmetics'''

        super().compile(compiler_state)
        self.pcap_obj.compile_offsets(compiler_state)

class U32ProgIndexLoad(U32Helper):
    '''Perform arithmetic operations.
    '''

    def compile(self, compiler_state=None):
        '''Compile arithmetics'''
        super().compile(compiler_state)
        self.pcap_obj.compile_offsets(compiler_state)

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


class U32ProgComp(U32Helper):
    '''Perform arithmetic comparisons.
    '''

    def compile(self, compiler_state=None):
        '''Compile comparison between operands'''

        left = self.pcap_obj.left
        right = self.pcap_obj.right

        super().compile(compiler_state)
        super().compile_offsets(compiler_state)
        self.add_code(self.pcap_obj.get_offset_code(self.helper_id))

        if left.result is not None and right.result is not None:
            self.pcap_obj.result = compute(left.result, self.attribs["op"], right.result)
            return

        if right.result is None:
            raise ValueError("Only static expressions are allowed for values")
        try:
            location = left.attribs["loc"].attribs["match_object"]
        except AttributeError:
            location = int(left.attribs["loc"])

        try:
            size = left.attribs["size"]
        except KeyError:
            size = 4

        self.add_code([
            U32LD(location=location, size=size),
            U32SH(shift=0),
            U32AND(),
            U32Compare(lower=right.result, upper=right.result)
        ])


class U32Immediate(U32Helper):
    '''Fake leafe for immediate ops
    '''
    def compile(self, compiler_state=None):
        self.pcap_obj.result = self.match_object

class U32ProgArOp(U32Helper):
    '''Perform arithmetic operations.
    '''

    def compile(self, compiler_state=None):
        '''Compile arithmetics'''

        left = self.pcap_obj.left
        right = self.pcap_obj.right

        super().compile(compiler_state)

        if self.left.result is not None and self.right.result is not None:
            self.pcap_obj.result = compute(left.result, self.attribs["op"], right.result)

def dispatcher(obj):
    '''Return the correct code helper'''
    return getattr(sys.modules[__name__], f"U32{obj.__class__.__name__}")(obj)
