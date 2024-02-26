#!/usr/bin/python3

'''Generic policy definitions'''

from pcap_parser import PARSER
from code_objects import finalize
from bpf_objects import CBPFCompilerState


ACTIONS = ["DROP", "ACCEPT"]  # basic actions, extension - TBA

class PolicyEntry():
    '''Generic policy rule'''
    def __init__(self, action, pfilter, order=100, model=None):
        self.action = action
        self.pfilter = pfilter
        self.order = order
        self.model = model
        self.compiled = None

    def parse(self):
        '''Invoke parser on rule'''
        self.compiled = finalize(PARSER.parse(self.pfilter))

    def add_helper(self, helper):
        '''Trim parsed expression'''
        self.compiled.add_helper(helper)

    def drop_type(self, to_drop):
        '''Trim parsed expression'''
        self.compiled.drop_type(to_drop)

    def compile(self, compiler_state=CBPFCompilerState()):
        '''Compile the expression'''
        self.compiled.compile(compiler_state)
        self.compiled.resolve_refs()

    def dump_code(self, helper_id, fmt, options):
        '''Get code for the corresponding helper_id'''
        for helper in self.compiled.helpers:
            if helper.helper_id == helper_id:
                return helper.dump_code(fmt, options)


class FirewallPolicy():
    '''Class representing a firewall policy'''
    def __init__(self):
        self.rules = []

    def add_entry(self, entry):
        '''Add a policy entry'''
        for index in range(0, len(self.rules)):
            rule = self.rules[index]
            if rule.order > entry.order:
                self.rules.insert(index + 1, entry)
                return
        self.rules.append(entry)
