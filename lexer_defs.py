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

reserved = {
    'dst' : 'DST',
    'src' : 'SRC',
    'host' : 'HOST',
    'gateway' : 'GATEWAY',
    'net' : 'NET',
    'netmask' : 'NETMASK',
    'port' : 'PORT',
    'portrange' : 'PORTRANGE',
    'proto' : 'PROTO',
    'protochain' : 'PROTOCHAIN',
    'cbyte' : 'CBYTE',
    'atalk' : 'ATALK',
    'aarp' : 'AARP',
    'decnet' : 'DECNET',
    'lat' : 'LAT',
    'sca' : 'SCA',
    'morpc' : 'MOPRC',
    'mopdl' : 'MOPDL',
    'broadcast' : 'TK_BROADCAST', 
    'multicast' : 'TK_MULTICAST',
    'inbound' : 'INBOUND',
    'outbound' : 'OUTBOUND',
    'ifindex' : 'IFINDEX',
    'type' : 'TYPE',
    'subtype' : 'SUBTYPE',
    'dir' : 'DIR',
    'addr1' : 'ADDR1',
    'addr2' : 'ADDR2',
    'addr3' : 'ADDR3',
    'addr4' : 'ADDR4',
    'ra' : 'RA',
    'ta' : 'TA',
    'link' : 'LINK',
    'len' : 'LEN',
    'ip6' : 'IPV6',
    'imcp6' : 'ICMPV6',
    'ah' : 'AH',
    'esp' : 'ESP',
    'vlan' : 'VLAN',
    'mpls' : 'MPLS',
    'ppoed' : 'PPPOED',
    'ppoes' : 'PPPOES',
    'geneve' : 'GENEVE',
    'iso' : 'ISO',
    'esis' : 'ESIS',
    'clnp' : 'CLNP',
    'isis' : 'ISIS',
    'l1' : 'L1',
    'l2' : 'L2',
    'iih' : 'IIH',
    'lsp' : 'LSP',
    'snp' : 'SNP',
    'csnp' : 'CSNP',
    'psnp' : 'PSNP',
    'stp' : 'STP',
    'ipx' : 'IPX',
    'netbeui' : 'NETBEUI',
    'lane': 'LANE',
    'llc' : 'LLC',
    'metac' : 'METAC',
    'bcc' : 'BCC',
    'sc' : 'SC',
    'ilmic' : 'ILMIC',
    'oamf4ec' : 'OAMF4EC',
    'oamf4sc' : 'OAMF4SC',
    'oam' : 'OAM',
    'oamf4' : 'OAMF4',
    'connectmsg' : 'CONNECTMSG',
    'metaconnect' : 'METACONNECT',
    'vpi' : 'VPI',
    'vci' : 'VCI',
    'radio' : 'RADIO',
    'fisu' : 'FISU',
    'lssu' : 'LSSU',
    'msu' : 'MSU',
    'hfisu' : 'HFISU',
    'hlssu' : 'HLSSU',
    'hmsu' : 'HMSU',
    'sio' : 'SIO',
    'opc' : 'OPC',
    'dpc' : 'DPC',
    'slc' : 'SLS',
    'hsio' : 'HSIO',
    'hopc' : 'HOPC',
    'hdpc'  :'HDPC',
    'hsls' : 'HSLS',
    'or' : 'OR',
    'and' : 'AND',
    'not' : 'NOT',
    'ip' : 'IP',
    'arp' : 'ARP',
    'rarp' : 'RARP',
    'sctp' : 'SCTP',
    'tcp' : 'TCP',
    'udp' : 'UDP',
    'icmp' : 'ICMP',
    'icmp6' : 'ICMPV6',
    'igmp' : 'IGMP',
    'igrp' : 'IGRP',
    'pim' : 'PIM',
    'vrrp' : 'VRRP',
    'carp' : 'CARP'
}

tokens = [
    "ADD", "SUB", "MUL", "DIV", "MOD", "A_AND", "A_OR", "XOR", 
    'LESS', 'GREATER',
    'GEQ', 'LEQ', 'NEQ',
    'LSH', 'RSH',
    'LPAREN', 'RPAREN',
    'NUM', 'ADDR_V4', 'ADDR_V6', 'STRING_LITERAL', 'NET_V4', 'NET_V6',
    'LBRA', 'RBRA', 'EQUAL',
] + list(reserved.values())

literals = [":"]

def t_addr_net_v4(t):
    r'\d+\.\d+\.\d+\.\d+(\/\d+){0,1}'
    if t.value.find('/') > 0:
        t.type = 'NET_V4'
    else:
        t.type = 'ADDR_V4'
    return t

def t_addr_net_v6_variant_a(t):
    r'(([a-fA-F0-9]{0,4}:){2,7}[a-fA-F0-9]{0,4})(\/\d+){0,1}'
    if t.value.find('/') > 0:
        t.type = 'NET_V6'
    else:
        t.type = 'ADDR_V6'
    return t

def t_addr_net_v6_variant_b(t):
    r'(([A-F0-9]{0,4}:){7}\d+\.\d+\.\d+\.\d+)(\/\d+){0,1}'
    if t.value.find('/') > 0:
        t.type = 'NET_V6'
    else:
        t.type = 'ADDR_V6'
    return t


t_LESS = r'<'
t_GREATER = r'>'
t_GEQ = r'>='
t_LEQ = r'<='
t_NEQ = r'!='
t_EQUAL = r'=='

t_LPAREN = r'\('
t_RPAREN = r'\)'
t_LBRA = r'\['
t_RBRA = r'\]'

t_ADD = r"\+"
t_SUB = r"-"
t_MUL = r"\*"
t_DIV = r"\/"
t_MOD = "\%"
t_A_AND = "\&"
t_A_OR = "\|"
t_XOR =  "\^"
t_LSH = r'<<'
t_RSH = r'>>'

def t_not_alternative(t):
    r'\!'
    t.type = 'NOT'
    return t

def t_ZZ_STRING_LITERAL(t):
    r'\w+'
    t.type = reserved.get(t.value.lower(), 'STRING_LITERAL')
    if (t.value.isnumeric()):
        t.value = int(t.value)
        t.type = 'NUM'
    return t

t_NUM = r'\d+'

def t_error(t):
    if t.value[0] != ' ':
        print("Illegal character '%s'" % t.value[0])
    t.lexer.skip(1)

