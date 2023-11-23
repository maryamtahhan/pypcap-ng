''' Pure python implementation of the pcap language parser.
Compiler backends.
'''


#
# Copyright (c) 2023 Red Hat, Inc., Anton Ivanov <anivanov@redhat.com>
# Copyright (c) 2023 Cambridge Greys Ltd <anton.ivanov@cambridgegreys.com>
#

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

class AbstractProgram():
    '''Chunk of code - fragments can be matchers or other programs'''
    def __init__(self, parent=None, frags=None, label=None, attribs=None):

        if attribs is not None:
            self.attribs = attribs.copy()
            try:
                self.attribs["quals"] = set(attribs["quals"])
            except KeyError:
                pass
            return

        self.attribs = dict()
        self.frags = frags
        self.frag_refs_resolved = False
        self.compiled = False
        self.parent = parent
        self.set_parent()
        self.code = []
        self.loc = COMPILER_STATE.get_loc()
        self.attribs["quals"] = set()
        self.result = None # evaluation result - catch constant expressions

    def drop_frags(self):
        '''Drop any subprograms created by default or added later -
           we need only the code produced up to this level
        '''
        self.attribs["frags"] = []

    def __eq__(self, other):
        '''We are only interested in equality of the generated code.'''
        return self.code == other.code

    def __repr__(self):
        '''Program (fragment) representation'''
        return "".join(self.frags)

    def get_code(self):
        '''Resulting code dump'''
        code = []
        for frag in self.frags:
            code.extend(frag.get_code())
        code.extend(self.code)
        return code

    def add_quals(self, quals):
        '''Resulting code dump'''
        for frag in self.frags:
            frag.add_quals(quals)
        try:
            self.attribs["quals"] = self.attribs["quals"] | quals
        except TypeError:
            self.attribs["quals"] = self.attribs["quals"] | set([quals])
            

    def compile(self, branch_state):
        '''Compile the program'''
        if not self.compiled:
            for frag in self.frags:
                frag.compile(branch_state)
            self.compiled = True

    def set_parent(self):
        '''Set parent for all code fragments.'''
        for frag in self.frags:
            frag.parent = self
            frag.set_parent()

    def replace_value(self, old, new, index=None):
        '''Ask all code fragments to replace a value.
           Let the code fragment internals actually handle it.
           Ultimately recurses to the replace_value method in 
           all instructions.
        '''
        for insn in self.get_code():
            insn.replace_value(old, new)
    

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

