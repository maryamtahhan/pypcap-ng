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

LEFT = 'left'
RIGHT = 'right'
OP = 'op'
OBJ = 'obj'
QUAL = 'qual'
OBJTYPE = 'obj_type'
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

class Head(Expr):
    def __init__(self, qual):
        self[QUAL] = qual

class Obj(Expr):
    def __init__(self, obj, obj_type=None):
        self[OBJ] = obj
        self[OBJTYPE] = obj_type

class Proto(Expr):
    def __init__(self, proto):
        self[PROTO] = proto


