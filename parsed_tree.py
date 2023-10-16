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

class Expr(dict): pass

class BinOp(Expr):
    def __init__(self, left, right, op):
        self[LEFT] = left
        self[RIGHT] = right
        self[OP] = op

class Match(Expr):
    def __init__(self, obj):
        self[OBJ] = obj

class UnOp(Expr):
    def __init__(self, obj, op):
        self[OBJ] = obj
        self[OP] = op

class Obj(Expr):
    def __init__(self, obj, objtype=None, quals=[]):
        self[OBJ] = obj
        self[OBJTYPE] = objtype
        self[QUALS] = quals

    def quals(self, new_quals=None):
        '''Set/reset qualifiers'''

        if new_quals is not None:
            self[QUALS] = new_quals
        return self[QUALS]
        
class Head(Obj):
    def __init__(self, quals):
        super().__init__(self, None, quals=quals)

class Proto(Expr):
    def __init__(self, proto):
        self[PROTO] = proto

def serialize(tree):
    '''Serialize an object tree in a human readable form'''
    return dumps(tree, indent=4)
