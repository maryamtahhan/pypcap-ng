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

LEFT = 'left'
RIGHT = 'right'
OP = 'op'
OBJ = 'obj'
QUAL = 'qual'
OBJTYPE = 'obj_type'
PROTO = 'proto'

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
    '''term     : rterm
                | NOT rterm
    '''
    if len(p) == 3:
        p[0] = UnOp(p[2], p[1])
    else:
        p[0] = p[1]

def p_rterm(p):   
    '''rterm    : head id
                | pname
                | other
    '''
    if len(p) == 3:
        p[0] = Obj(p[2], p[1])
    else:
        p[0] = p[1]

def p_head(p):
    '''head     : pname dqual aqual
	            | pname dqual
	            | pname aqual
                | dqual aqual
                | dqual
                | aqual
	            | pname PROTO
	            | pname PROTOCHAIN
                | pname GATEWAY
                |
    '''
    p[0] = Head(p[1:])
        

def p_pname(p):
    '''pname    : LINK
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

def p_dqual(p):
    '''dqual : SRC
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
    '''
    p[0] = p[1]

def p_other(p):
    '''other    : pname TK_BROADCAST
                | pname TK_MULTICAST
                | LESS NUM
                | GREATER NUM
                | INBOUND
                | OUTBOUND
                | IFINDEX NUM
                | VLAN NUM	
                | VLAN	
                | MPLS NUM	
                | MPLS
                | PPPOED
                | PPPOES NUM
                | PPPOES
                | GENEVE NUM
                | GENEVE
    '''
    if len(p) == 2:
        p[0] = Obj(None, obj_type=p[1])
    else:
        p[0] = Obj(p[2], obj_type=p[1])

def p_aqual(p):
    '''aqual : HOST
             | NET
             | PORT
             | PORTRANGE
             | GATEWAY
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

