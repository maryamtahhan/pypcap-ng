# !/usr/bin/python3

''' pure python implementation of the pcap language parser
'''

#
# Copyright (c) 2022 Red Hat, Inc., Anton Ivanov <anivanov@redhat.com>
# Copyright (c) 2022 Cambridge Greys Ltd <anton.ivanov@cambridgegreys.com>
#
# Dual Licensed under the GNU Public License Version 2.0 and BSD 3-clause
#
#

from lexer_defs import tokens
from json import dumps

LEFT = 'left'
RIGHT = 'right'
OP = 'op'
OBJ = 'obj'
QUALS = 'qual'
OBJTYPE = 'objtype'
PROTO = 'proto'

# Classes inherit from dict, this makes it trivial to serialize them.
# properties that should be serialized become members of the dict, 
# properties that should not be serialized will be just properties.

class Expr(dict): 
    '''Parsed expression and associated code.
    '''
    def __init__(self, compiled=None):
        self.code = compiled

    def quals(self, new_quals=None):
        '''Set/reset qualifiers'''

        if new_quals is not None:
            self[QUALS] = new_quals
        return self[QUALS]

class BinOp(Expr):
    def __init__(self, left, right, op):
        super().__init__(self)
        self[LEFT] = left
        self[RIGHT] = right
        self[OP] = op

    def quals(self, new_quals=None):
        '''Set/reset qualifiers'''

        if new_quals is not None:
            if (isinstance(self[LEFT], Expr)):
                self[LEFT].quals(new_quals)
            if (isinstance(self[RIGHT], Expr)):
                self[RIGHT].quals(new_quals)
        
        return None


class Match(Expr):
    def __init__(self, obj):
        super().__init__(self)
        self[OBJ] = obj

class UnOp(Expr):
    def __init__(self, obj, op):
        super().__init__(self)
        self[OBJ] = obj
        self[OP] = op

class Obj(Expr):
    def __init__(self, obj, objtype=None, quals=[]):
        super().__init__(self)
        self[OBJ] = obj
        self[OBJTYPE] = objtype
        self[QUALS] = quals

       
class Head(Obj):
    def __init__(self, quals):
        super().__init__(self, None, quals=quals)

class Proto(Expr):
    def __init__(self, proto):
        self[PROTO] = proto

def serialize(tree):
    '''Serialize an object tree in a human readable form'''
    return dumps(tree, indent=4)
