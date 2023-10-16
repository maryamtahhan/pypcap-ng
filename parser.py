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

from parsed_tree import LEFT, RIGHT, OP, OBJ, QUALS, OBJTYPE, PROTO
from parsed_tree import Expr, BinOp, Match, UnOp, Head, Obj, Proto

precedence = (
    ('left', 'OR', 'AND'),
    ('nonassoc', 'NOT'),
    ('left', 'LSH', 'RSH'),
)

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
        p[2].quals(p[1].quals())
        p[0] = p[2]
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
    '''other    : bmcast
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
        p[0] = Obj(None, quals=[p[1]])
    else:
        p[0] = Obj(int(p[2]), quals=[p[1]], objtype='NUM')

def p_bmcast(p):
    '''bmcast   : pname TK_BROADCAST
                | pname TK_MULTICAST
    '''
    p[0] = Obj(None, quals=[p[1], p[2]])
    

def p_aqual(p):
    '''aqual : HOST
             | NET
             | PORT
             | PORTRANGE
             | GATEWAY
    '''
    p[0] = p[1]

def p_id(p):
    '''id : num
          | addr
          | hostname
          | net
    '''
    p[0] = p[1]

def p_num(p):
    '''num : NUM 
    '''
    p[0] = Obj(int(p[1]), objtype='NUM')

def p_addr(p):
    '''addr : addr4
            | addr6
    '''
    p[0] = p[1]

def p_addr4(p):
    '''addr4 : ADDR_V4
    '''
    p[0] = Obj(p[1], objtype='ADDR_V4')

def p_addr6(p):
    '''addr6 : ADDR_V6
    '''
    p[0] = Obj(p[1], objtype='ADDR_V6')

def p_net(p):
    '''net  : net4
            | net6
    '''
    p[0] = p[1]

def p_net4(p):
    '''net4 : NET_V4
    '''
    p[0] = Obj(p[1], objtype='NET_V4')

def p_net6(p):
    '''net6 : NET_V6
    '''
    p[0] = Obj(p[1], objtype='NET_V6')

def p_hostname(p):
    '''hostname : STRING_LITERAL
    '''
    p[0] = Obj(p[1], objtype='STRING_LITERAL')


lexer = lex.lex(module=lexer_defs)
PARSER = yacc.yacc()

