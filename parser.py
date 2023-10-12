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

import ply.lex as lex
import ply.yacc as yacc
from lexer_defs import tokens
import lexer_defs

precedence = (
    ('left', 'OR', 'AND'),
    ('nonassoc', 'NOT'),
    ('left', 'LSH', 'RSH'),
)


class Expr: pass

class BinOp(Expr):
    def __init__(self, left, right, op):
        self.left = left
        self.right = right
        self.op = op

    def __repr__(self):
        return "({}) {} ({})".format(self.left, self.op, self.right)

class Match(Expr):
    def __init__(self, obj):
        self.obj = obj

    def __repr__(self):
        return "{}".format(self.obj)

class UnOp(Expr):
    def __init__(self, obj, op):
        self.obj = obj
        self.op = op

    def __repr__(self):
        return "{}->{}".format(self.op, self.obj)

class Qual(Expr):
    def __init__(self, obj, qual):
        self.obj = obj
        self.qual = qual

    def __repr__(self):
        return "{}=>{}".format(self.qual, self.obj)

class Obj(Expr):
    def __init__(self, term):
        self.term = term

    def __repr__(self):
        return "[{}]".format(self.term)

class Proto(Expr):
    def __init__(self, proto):
        self.proto = proto

    def __repr__(self):
        return "|{}|".format(self.proto)


def p_binary_operators(p):
    '''expression : expression AND expression
                  | expression OR expression
                  | LPAREN expression RPAREN
                  | term
    '''
    if len(p) == 4:
        if p[1] != '(':
            p[0] = BinOp(p[1], p[3], p[2])
        else:
            p[0] = p[2]
    else:
        p[0] = Match(p[1])

def p_term(p):
    '''term : qual id
            | NOT qual id
            | proto
            | NOT proto
    '''
    if len(p) == 4:
        p[0] = UnOp(Qual(p[3], p[2]), p[1])
    else:
        p[0] = Qual(p[2], p[1])

def p_proto(p):
    '''proto :  LINK
	| IP
	| ARP
	| RARP
	| SCTP
	| TCP	
	| UDP
	| ICMP
	| IGMP
	| IGRP
	| PIM	
	| VRRP
	| CARP
	| ATALK
	| AARP	
	| DECNET
	| LAT
	| SCA
	| MOPDL
	| MOPRC
	| IPV6	
	| ICMPV6
	| AH
	| ESP
	| ISO
	| ESIS
	| ISIS
	| L1	
	| L2
	| IIH
	| LSP
	| SNP
	| PSNP
	| CSNP
	| CLNP
	| STP	
	| IPX
	| NETBEUI
	| RADIO
'''
    p[0] = Proto(p[1])

def p_qual(p):
    '''qual : SRC
            | DST
            | SRC OR DST
            | DST OR SRC
            | DST AND SRC
            | SRC AND DST
            | ADDR1
            | ADDR2
            | ADDR3
            | ADDR4
            | RA
            | TA
            | HOST
            | NET
            | PORT
            | PORTRANGE
    '''
    p[0] = p[1]

def p_id(p):
    '''id : NUM
          | ADDR_V4
          | ADDR_V6
          | STRING_LITERAL
          | NET_V4
          | NET_V6
    '''
    p[0] = Obj(p[1])

    
lexer = lex.lex(module=lexer_defs)
PARSER = yacc.yacc()

