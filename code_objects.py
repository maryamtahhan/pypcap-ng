''' Pure python implementation of the pcap language parser.
Compiler backends.
'''


#
# Copyright (c) 2023 Red Hat, Inc., Anton Ivanov <anivanov@redhat.com>
# Copyright (c) 2023 Cambridge Greys Ltd <anton.ivanov@cambridgegreys.com>
#

import json
from header_constants import IP_PROTOS

NEXT_MATCH = "__next_match"
PARENT_NEXT = "__parent_next"
LAST_INSN = "__last_insn"
SUCCESS = "__success"
FAIL = "__fail"


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

class AbstractCode(dict):
    '''Generic code class (bpf, instructions to flower, instructions
    to hardware, etc.
    '''
    def __init__(self, label=None):
        self.values = []
        if label is not None:
            if isinstance(label, list) and len(label) > 0:
                self.labels = set(label)
            elif isinstance(label, set):
                self.labels = set() | label
            else:
                self.labels = set([label])
        else:
            self.labels = set()
        self.loc = COMPILER_STATE.get_loc()
        self.code = []

    def has_label(self, label):
        '''Check if instruction has a label'''
        return label in self.labels

    #pylint: disable=unused-argument
    def obj_dump(self, counter):
        '''Dump object code'''
        return None

    def add_label(self, label):
        '''Add a label'''
        if label is None:
            raise TypeError
        self.labels = self.labels | set([label])

    def replace_label(self, label, newlabel):
        '''Replace a label'''
        if newlabel is None:
            raise TypeError
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

    def get_code(self):
        "Return compiled code"
        return self.code

    def get_loc(self):
        "Return loc"
        return self.loc

    def __eq__(self, other):
        '''Equal - needed for tests'''
        return self.labels == other.labels

class AbortBranch(Exception):
    '''Indicate that this branch should not be compiled any further
       terminates the helper chain
    '''
    def __init__(self, message):
        super().__init__(message)


class AbstractProgram():
    '''Chunk of code - fragments can be matchers or other programs'''
    def __init__(self, frags=None, attribs=None, match_object=None, ip_version=4):

        self.ip_version = ip_version

        if attribs is not None:
            self.attribs = attribs.copy()
            return

        # serializable attributes - must not contain
        # anything that does not need to go into the json form

        self.attribs = {}

        # unique number used in generating jump labels.

        self.loc = COMPILER_STATE.get_loc()

        self.ext_label = f"__ext__{self.loc}"
        if attribs is None:
            self.attribs.update({
                "on_success": NEXT_MATCH,
                "on_failure": FAIL,
                "name":"generic",
            })

            if match_object is not None:
                self.attribs["match_object"] = match_object

        else:
            self.attribs = attribs.copy()
            try:
                self.frags = attribs["frags"]
            except KeyError:
                pass


        # list of code fragments which sit under this node in
        # the hierarchy

        self.frags = frags

        # are references to which frags are next resolved or not
        # candidate for removal

        self.frag_refs_resolved = False

        # compiled ?

        self.compiled = False
        self.compiled_offsets = False

        # Code elements. May be different types

        self.code = {}
        self.offset_code = {}


        # qualifiers which are not protos - src, dst, etc

        self.attribs["quals"] = []

        # evaluation of constant expressions

        self.result = None

        # helper class instances

        self.helpers = []

    def add_helper(self, dispatcher):
        '''Add a helper class used for compilation, offload, etc.
           Helper classes take one argument - the "lead" class.
           Helper classes must offer a compile() method.
        '''
        for frag in self.frags:
            frag.add_helper(dispatcher)

        try:
            if isinstance(self.attribs["loc"], list):
                for loc in self.attribs["loc"]:
                    loc.add_helper(dispatcher)
        except KeyError:
            pass

        self.helpers.append(dispatcher(self))

    def drop_frags(self):
        '''Drop any subprograms created by default or added later -
           we need only the code produced up to this level
        '''
        self.attribs["frags"] = []

    def drop_type(self, obj_class):
        '''Drop all subprograms of this class'''
        new_frags = []
        for frag in self.frags:
            if not isinstance(frag, obj_class):
                frag.drop_type(obj_class)
                new_frags.append(frag)
        self.frags = new_frags

    def __eq__(self, other):
        '''By default we return non-equal'''

        return self.name == other.name and \
                self.ip_version == other.ip_version and \
                self.attribs.get("match_object") == other.attribs.get("match_object") and \
                self.frags == other.frags and \
                self.attribs["quals"] == other.attribs["quals"]

    def __repr__(self):
        '''Program (fragment) representation'''
        return "".join(self.frags)

    def get_code(self, code_id):
        '''Resulting code dump'''
        code = []
        for frag in self.frags:
            code.extend(frag.get_code(code_id))
        try:
            code.extend(self.code[code_id])
        except KeyError:
            pass
        return code

    def get_offset_code(self, code_id):
        '''Get offset specific code'''
        code = []
        try:
            # top level
            for frag in self.attribs["offset_frags"]:
                code.extend(frag.get_offset_code(code_id))
        except KeyError:
            for frag in self.frags:
                code.extend(frag.get_offset_code(code_id))
        try:
            code.extend(self.offset_code[code_id])
        except KeyError:
            pass
        return code

    def resolve_refs(self):
        '''Second pass'''
        for helper in self.helpers:
            code = self.get_code(helper.helper_id)
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

    def add_frags(self, frags):
        '''Add frags'''
        if not isinstance(frags, list):
            frags = [frags]
        for frag in frags:
            if not frag in self.frags:
                self.frags.append(frag)

    def add_quals(self, quals):
        '''Add qualifiers'''

        if not isinstance(quals, list):
            quals = [quals]

        for qual in quals:
            if not qual in self.attribs["quals"]:
                self.attribs["quals"].append(qual)

    def update_labels(self):
        '''Update code start/end labels.
           This should be applicable to both offload and bytecode.
        '''
        for code_id in self.code:
            code = self.get_code(code_id)
            if len(code) > 0:
                code[0].add_label(f"__start__{self.loc}")
                code[-1].add_label(f"__end__{self.loc}")

    def add_code(self, code, code_id):
        '''Add code and update jump label in last frag
           This should be applicable to both offload and bytecode.
        '''
        if len(self.frags) > 0:
            self.frags[-1].replace_value(NEXT_MATCH, self.ext_label)
        self.code[code_id].extend(code)
        self.code[code_id][0].add_label(self.ext_label)

    def add_offset_code(self, code, code_id):
        '''Add offset specific code.
           This is bytecode specific and will not work for most
           offloads. However, it is sufficiently generic to keep here.
        '''
        try:
            self.offset_code[code_id].extend(code)
        except KeyError:
            self.offset_code[code_id] = code

    def drop_branch(self, helper=None):
        '''Drop all code on this branch'''
        for frag in self.frags:
            frag.drop_branch(helper)
        if helper is not None:
            self.code[helper.helper_id] = []
        else:
            for key in self.code:
                self.code[key] = []

    def compile(self, branch_state):
        '''Compile the program'''
        if not self.compiled:
            for frag in self.frags:
                frag.compile(branch_state)

        for helper in self.helpers:
            if self.code.get(helper.helper_id) is None:
                self.code[helper.helper_id] = []
            if not helper.compiled:
                try:
                    helper.compile(branch_state)
                except AbortBranch:
                    for frag in self.frags:
                        frag.drop_branch()
                    break

        for frag in self.frags:
            frag.update_labels()

        for index in range(0, len(self.frags) - 1):
            self.frags[index].replace_value(
                NEXT_MATCH, self.frags[index + 1].get_start_label())
            for nested_frag in self.frags[index].frags:
                nested_frag.replace_value(PARENT_NEXT, self.frags[index + 1].get_start_label())

        self.compiled = True

    def second_pass(self, branch_state):
        '''Second pass'''
        if not self.compiled:
            raise ValueError("Invalid state - compile first")

        for helper in self.helpers:
            helper.second_pass(branch_state)

        for frag in self.frags:
            frag.second_pass(branch_state)

    def obj_dump(self, code_id):
        '''Dump "opcodes"'''
        if not self.compiled:
            return None
        result = []
        for ins in self.get_code(code_id):
            result.append(ins.obj_dump())
        return result

    def compile_offsets(self, branch_state=None):
        '''Compile the code and mark it as compiled'''
        if not self.compiled_offsets:
            for frag in self.frags:
                frag.compile_offsets(branch_state)
            self.compiled_offsets = True
            for helper in self.helpers:
                helper.compile_offsets(branch_state)


    def replace_value(self, old, new):
        '''Ask all code fragments to replace a value.
           Let the code fragment internals actually handle it.
           Ultimately recurses to the replace_value method in
           all instructions.
        '''

        for code_id in self.code:
            for insn in self.get_code(code_id):
                insn.replace_value(old, new)

    def get_start_label(self):
        '''Set start label'''
        if len(self.frags) > 0:
            return self.frags[0].get_start_label()
        return f"__start__{self.loc}"

    @property
    def offset(self):
        '''match_object getter'''
        return self.attribs["offset"]

    @property
    def match_object(self):
        '''match_object getter'''
        return self.attribs["match_object"]


    @property
    def labels(self):
        '''Labels for this piece of code'''
        return self.attribs.get("labels")

    @property
    def name(self):
        '''Frag list used to build this piece of code'''
        return self.attribs.get("name")

    @property
    def frags(self):
        '''Frag list used to build this piece of code'''
        return self.attribs.get("frags")

    @frags.setter
    def frags(self, value):
        '''Frag list setter'''
        if value is None:
            self.attribs["frags"] = []
        elif not isinstance(value, list):
            self.attribs["frags"] = [value]
        else:
            self.attribs["frags"] = value

    @property
    def quals(self):
        '''Qualifiers used to build match'''
        return self.attribs.get("quals")

class AbstractHelper():
    '''Basic helper class'''
    def __init__(self, expr):
        self.pcap_obj = expr
        self.helper_id = "generic"
        self.compiled = False
        self.compiled_offsets = False

    #pylint: disable=unused-argument
    def compile(self, compiler_state=None):
        '''compile all code for the same helper type'''
        self.compiled = True

    #pylint: disable=unused-argument
    def compile_offsets(self, compiler_state=None):
        '''compile all code for the same helper type'''
        self.compiled_offsets = True
        return 0

    def second_pass(self, compiler_state=None):
        '''Second compiler pass where needed. f.e u32'''

    def get_code(self):
        '''Get the code generated by this helper'''
        return self.pcap_obj.get_code(self.helper_id)

    def dump_code(self, fmt, options):
        '''Get the code generated by this helper'''
        return


class ProgSuccess(AbstractProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, attribs=None):
        super().__init__(attribs=attribs)
        self.attribs["name"] = "success"


class ProgFail(AbstractProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, attribs=None):
        super().__init__(attribs=attribs)
        self.attribs["name"] = "fail"


class ProgL2(AbstractProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, match_object=None, attribs=None):
        if attribs is not None:
            super().__init__(attribs=attribs)
        else:
            super().__init__(match_object=match_object)
            self.attribs["name"] = "l2"


class Prog8021Q(AbstractProgram):
    '''Vlan matcher'''
    def __init__(self, match_object,  attribs=None):
        if attribs is not None:
            super().__init__(attribs=attribs)
        else:
            super().__init__(frags=[ProgL2(match_object="qtag")], match_object=match_object)

class ProgL3(AbstractProgram):
    '''Layer 3 protocol matcher'''
    def __init__(self, match_object=None, attribs=None, ip_version=4):
        if attribs is not None:
            super().__init__(attribs=attribs)
        else:
            super().__init__(match_object=match_object, frags=[ProgIP(ip_version=ip_version)])
            self.attribs["name"] = "l3"

class ProgIP(AbstractProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, attribs=None, ip_version=4):
        if attribs is None and ip_version == 4:
            match_object = "ip"
        else:
            match_object = "ip6"
        super().__init__(frags=[ProgL2(match_object=match_object)], attribs=attribs, ip_version=ip_version)
        if ip_version == 4:
            self.attribs["name"] = "ip"
        else:
            self.attribs["name"] = "ip6"

# pylint: disable=invalid-name
def ProgIP6(attribs=None):
    '''Constructor-like Function which invokes IP with
       v6 parameters
    '''
    return ProgIP(attribs=attribs, ip_version=6)

class ProgTCP(ProgL3):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, attribs=None):
        if attribs is None:
            super().__init__(match_object=IP_PROTOS["tcp"])
        else:
            super().__init__(attribs=attribs)

        self.attribs["name"] = "tcp"

class ProgUDP(AbstractProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, attribs=None, ip_version=4):
        super().__init__(frags=[
                ProgIP(ip_version=ip_version),
                ProgL3(match_object=IP_PROTOS["udp"])
            ], attribs=attribs)
        self.attribs["name"] = "udp"

class ProgPort(AbstractProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, match_object=None, frags=None, attribs=None, ip_version=4):

        if frags is None and attribs is None:
            frags = [ProgIP(ip_version=ip_version)]

        super().__init__(match_object=match_object, frags=frags, attribs=attribs)
        self.attribs["name"] = "port"

class ProgPortRange(AbstractProgram):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def __init__(self, match_object=None, frags=None, attribs=None):

        super().__init__(match_object=match_object, frags=frags, attribs=attribs)
        self.attribs["name"] = "portrange"

        newfrags = []
        for frag in self.frags:
            if isinstance(frag, ProgArOp):
                self.attribs["loc"] = frag.frags
            else:
                newfrags.append(frag)
        self.attribs["frags"] = newfrags


class ProgIPv4(AbstractProgram):
    '''Basic match on v4 address or network.
    '''
    def __init__(self, match_object=None, attribs=None, add_ip_check=True, ip_version=4):

        if attribs is not None:
            super().__init__(attribs=attribs, ip_version=ip_version)
        else:
            super().__init__(match_object=match_object)
            if add_ip_check:
                self.frags = [ProgIP()]
        self.attribs["name"] = "ipv4"

    def add_quals(self, quals):
        '''Override add_quals to take care of "interesting" syntax'''
        super().add_quals(quals)
        if "srcordst" in self.quals or "srcanddst" in self.quals:
            left = ProgIPv4(match_object=self.match_object, add_ip_check=False)
            right = ProgIPv4(match_object=self.match_object, add_ip_check=False)
            left.add_quals("src")
            right.add_quals("dst")
            if "srcordst" in self.quals:
                self.frags.append(ProgOR(left=left, right=right))
            else:
                self.frags.append(ProgAND(left=left, right=right))

class ProgIPv6(AbstractProgram):
    '''Basic match on v6 address or network.
    '''
    def __init__(self, match_object=None, attribs=None, add_ip_check=True, ip_version=6):

        if attribs is not None:
            super().__init__(attribs=attribs, ip_version=6)
        else:
            super().__init__(match_object=match_object)
            if add_ip_check:
                self.frags = [ProgIP6()]
        self.attribs["name"] = "ipv6"

    def add_quals(self, quals):
        '''Override add_quals to take care of "interesting" syntax'''
        super().add_quals(quals)
        if "srcordst" in self.quals or "srcanddst" in self.quals:
            left = ProgIPv6(match_object=self.match_object, add_ip_check=False)
            right = ProgIPv6(match_object=self.match_object, add_ip_check=False)
            left.add_quals("src")
            right.add_quals("dst")
            if "srcordst" in self.quals:
                self.frags.append(ProgOR(left=left, right=right))
            else:
                self.frags.append(ProgAND(left=left, right=right))

class ProgNOT(AbstractProgram):
    '''Negate the result of all frags.
    '''
    def __init__(self, frags=None, attribs=None):
        # swap on_success and on_failure

        super().__init__(frags=frags, attribs=attribs)
        self.attribs["name"] = "not"

class ProgOR(AbstractProgram):
    '''Perform logical OR on left and right frag(s)
    '''
    def __init__(self, left=None, right=None, attribs=None):
        if attribs is None:
            self.right = right
            self.left = left
            super().__init__(frags=[self.left, self.right])
        else:
            super().__init__(attribs=attribs)
            self.left=attribs["frags"][0]
            self.right=attribs["frags"][1]
        self.attribs["name"] = "or"

class ProgAND(AbstractProgram):
    '''Perform logical AND on left and right frag(s)
    '''
    def __init__(self, left=None, right=None, attribs=None):
        if attribs is None:
            self.right = right
            self.left = left
            super().__init__(frags=[self.left, self.right])
        else:
            super().__init__(attribs=attribs)
            self.left=attribs["frags"][0]
            self.right=attribs["frags"][1]

        self.attribs["name"] = "and"

class ProgLoad(AbstractProgram):
    '''Load a value from packet address
    '''
    def __init__(self, loc=0, size=4, attribs=None):
        if attribs is None:
            super().__init__()
            self.attribs["loc"] = loc
            self.attribs["size"] = size
        else:
            super().__init__(attribs=attribs)
        self.attribs["name"] = "ar_load"

class ProgIndexLoad(AbstractProgram):
    '''Perform arithmetic operations.
    '''
    def __init__(self, frags=None, size=4, attribs=None):
        if attribs is None:
            super().__init__(frags=frags)
            self.attribs["size"] = size
        else:
            super().__init__(attribs=attribs)
        self.attribs["name"] = "ar_load"

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

class ProgOffset(AbstractProgram):
    '''Perform arithmetic comparisons.
    '''
    def __init__(self, frags=None, attribs=None):
        if attribs is None:
            super().__init__(frags=frags)
        else:
            super().__init__(attribs=attribs)
        self.attribs["name"] = "compute_offset"


class ProgComp(AbstractProgram):
    '''Perform arithmetic comparisons.
    '''
    def __init__(self, op=None, left=None, right=None, attribs=None):
        if attribs is None:
            super().__init__(frags=[left, right])
            self.attribs["op"] = op
        else:
            super().__init__(attribs=attribs)
        self.left = self.frags[0]
        self.right = self.frags[1]
        self.attribs["name"] = "ar_comp"


class Immediate(AbstractProgram):
    '''Fake leaf for immediate ops
    '''
    def __init__(self, match_object=None, attribs=None):
        if attribs is None:
            super().__init__(match_object=match_object)
        else:
            super().__init__(attribs=attribs)
        self.attribs["name"] = "immediate"

class ProgArOp(AbstractProgram):
    '''Perform arithmetic operations.
    '''
    def __init__(self, op=None, left=None, right=None, attribs=None):
        if attribs is None:
            super().__init__(frags=[left, right])
            self.attribs["op"] = "op"
        else:
            super().__init__(attribs=attribs)
        self.left = self.frags[0]
        self.right = self.frags[0]
        self.attribs["name"] = "ar_op"


class ProgramEncoder(json.JSONEncoder):
    '''Serializer to JSON'''

    def default(self, o):
        if isinstance(o, AbstractProgram):
            return o.attribs.copy()
        return json.JSONEncoder.default(self, o)

def loads_hook(obj):
    '''Custom JSON deserializer'''
    try:
        return JUMPTABLE[obj["name"]](attribs=obj)
    except KeyError:
        return None


def finalize(prog):
    '''Add success and failure return instructions to the end'''
    return AbstractProgram(frags=[prog, ProgSuccess(), ProgFail()])

JUMPTABLE = {
    "generic":AbstractProgram,
    "ip":ProgIP,
    "ip6":ProgIP6,
    "l2":ProgL2,
    "l3":ProgL3,
    "tcp":ProgTCP,
    "udp":ProgUDP,
    "port":ProgPort,
    "portrange":ProgPortRange,
    "ipv4":ProgIPv4,
    "ipv6":ProgIPv6,
    "not":ProgNOT,
    "or":ProgOR,
    "and":ProgAND,
    "fail":ProgFail,
    "success":ProgSuccess,
    "ar_comp":ProgComp,
    "ar_op":ProgArOp,
    "ar_load":ProgLoad,
    "index_load":ProgIndexLoad,
    "immediate":Immediate,
    "compute_offset":ProgOffset
}
