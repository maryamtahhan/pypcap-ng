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
from dispatcher import DISPATCH

precedence = (
    ('left', 'OR', 'AND'),
    ('nonassoc', 'NOT'),
    ('left', 'LSH', 'RSH'),
)

def p_operators(p):
    '''expression : binary_op
                  | negation
                  | brackets
                  | term
    '''
    p[0] = p[1]

def p_binary_operators(p):
    '''binary_op  : expression AND expression
                  | expression OR expression
    '''
    if p[2].lower() == 'or':
        p[0] = DISPATCH["or"](left=p[1], right=p[3])
    else:
        p[0] = DISPATCH["and"](left=p[1], right=p[3])

def p_brackets(p):
    '''brackets  : LPAREN expression RPAREN
    '''
    p[0] = p[2]

def p_negation(p):
    '''negation  : NOT expression'''
    p[0] = DISPATCH["not"](p[2])

def p_term(p):   
    '''term    : head id
                | pname
                | other
    '''
    if len(p) == 3:
        p[2].add_quals(p[1])
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
    p[0] = set(p[1:])
        

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
    try:
        p[0] = [DISPATCH["generic"](frags=MatchL2Proto(p[1]))]
    except KeyError:
        return [
            DISPATCH["generic"](
                frags=[
                    DISPATCH["ip"](),
                    DISPATCH["l3"](match_object=p[1]),
                ]
            )]

def p_dqual(p):
    '''dqual : SRC
             | DST
             | ADDR1
             | ADDR2
             | ADDR3
             | ADDR4
             | RA
             | TA
             | srcordst
             | srcanddst
    '''
    p[0] = p[1]

def p_srcordst(p):
    '''srcordst :  SRC OR DST
                 | DST OR SRC
    '''
    p[0] = "srcordst"
    
def p_srcanddst(p):
    '''srcanddst :  SRC AND DST
                 | DST AND SRC
    '''
    p[0] = "srcanddst"
    

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
    pass

def p_bmcast(p):
    '''bmcast   : pname TK_BROADCAST
                | pname TK_MULTICAST
    '''
    pass
    

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
    pass

def p_addr(p):
    '''addr : addr4
            | addr6
    '''
    p[0] = p[1]

def p_addr4(p):
    '''addr4 : ADDR_V4
    '''
    p[0] = DISPATCH["ipv4"](p[1])

def p_addr6(p):
    '''addr6 : ADDR_V6
    '''
    pass

def p_net(p):
    '''net  : net4
            | net6
    '''
    p[0] = p[1]

def p_net4(p):
    '''net4 : NET_V4
    '''
    p[0] = DISPATCH["ipv4"](p[1])

def p_net6(p):
    '''net6 : NET_V6
    '''
    pass

def p_hostname(p):
    '''hostname : STRING_LITERAL
    '''
    p[0] = p[1]


lexer = lex.lex(module=lexer_defs)
PARSER = yacc.yacc()

