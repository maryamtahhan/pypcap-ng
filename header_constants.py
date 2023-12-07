''' Pure python implementation of the pcap language parser.
Packet header constants
'''


#
# Copyright (c) 2023 Red Hat, Inc., Anton Ivanov <anivanov@redhat.com>
# Copyright (c) 2023 Cambridge Greys Ltd <anton.ivanov@cambridgegreys.com>
#


# Ethernet

ETHER = {
    "src": 0,
    "dst": 6,
    "proto": 12,
    "size": 14
}

IP = {
    "version": 0,
    "ihl": 1,
    "proto": 9,
    "src": 12,
    "dst": 16,
}

IP6 = {
    "version": 0,
    "src": 8,
    "dst": 24,
    "size": 40
}
# IPv6 will wait for now


ETH_PROTOS = {
    "ip": 0x0800,                    # Internet Protocol version 4 (IPv4)
    "arp":"0x0806",                 # Address Resolution Protocol (ARP)
    "wol": "0x0842", 	            # Wake-on-LAN
    "stream_reservation": 0x22EA,   # Stream Reservation Protocol
    "avtp": 0x22F0,         	    # Audio Video Transport Protocol (AVTP)
    "trill": 0x22F3,                # IETF TRILL Protocol
    "rarp": 0x8035,                 # Reverse Address Resolution Protocol (RARP)
    "appletalk": 0x809B, 	        # AppleTalk (Ethertalk)
    "aarp": 0x80F3, 	            # AppleTalk Address Resolution Protocol (AARP)
    "qtag": 0x8100, 	            # VLAN-tagged frame (IEEE 802.1Q)
    "slpp": 0x8102,                 # Simple Loop Prevention Protocol (SLPP)
    "vlacp": 0x8103, 	            # Virtual Link Aggregation Control Protocol (VLACP)
    "ipx": 0x8137,
    "qnx": 0x8204,
    "ip6": 0x86DD, 	                # Internet Protocol Version 6 (IPv6)
    "flow_control": 0x8808,         # Ethernet flow control
    "lacp": 0x8809, 	            # Link Aggregation Control Protocol (LACP)
    "cobranet": 0x8819,
    "mpls": 0x8847,              	# MPLS unicast
    "mmpls": 0x8848,                # MPLS multicast
    "ppoed": 0x8863,                # PPPoE Discovery Stage
    "ppoes": 0x8864,                # PPPoE Session Stage
    "hopeplug1": 0x887B,            # HomePlug 1.0 MME
    "eap8021x": 0x888E,             # EAP over LAN (IEEE 802.1X)
    "profinet": 0x8892,             # PROFINET Protocol
    "hyperscsi": 0x889A, 	        # HyperSCSI (SCSI over Ethernet)
    "ataoe": 0x88A2, 	            # ATA over Ethernet
    "ethercat": 0x88A4,             # EtherCAT Protocol
    "staq": 0x88A8,                 # Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel
    "powerlink": 0x88AB, 	        # Ethernet Powerlink
    "goose": 0x88B8,                # GOOSE (Generic Object Oriented Substation event)
    "gse": 0x88B9,                  # GSE (Generic Substation Events) Management Services
    "sv": 0x88BA,                   # SV (Sampled Value Transmission)
    "romon": 0x88BF,                # MikroTik RoMON
    "lldp": 0x88CC,                 # Link Layer Discovery Protocol (LLDP)
    "sercosiii": 0x88CD,            # SERCOS III
    "homepluggreen": 0x88E1,        # HomePlug Green PHY
    "mrc": 0x88E3,                  # Media Redundancy Protocol (IEC62439-2)
    "macsec": 0x88E5,               # IEEE 802.1AE MAC security (MACsec)
    "pbb": 0x88E7, 	                # Provider Backbone Bridges (PBB) (IEEE 802.1ah)
    "ptp":  0x88F7,                 # Precision Time Protocol (PTP) over IEEE 802.3 Ethernet
    "nc-si": 0x88F8,             	# NC-SI
    "prp": 0x88FB,                  # Parallel Redundancy Protocol (PRP)
    "cfm": 0x8902,                  # IEEE 802.1ag Connectivity Fault Management (CFM)
    "fcoe": 0x8906,                 # Fibre Channel over Ethernet (FCoE)
    "fcoei": 0x8914,     	        # FCoE Initialization Protocol
    "roce": 0x8915,              	# RDMA over Converged Ethernet (RoCE)
    "tte": 0x891D,                  # TTEthernet Protocol Control Frame (TTE)
    "1905.1": 0x893a,               # 1905.1 IEEE Protocol
    "hsr": 0x892F,                  # High-availability Seamless Redundancy (HSR)
    "ectp": 0x9000,                 # Ethernet Configuration Testing Protocol
    "redundancy": 0xF1C1            # Redundancy Tag IEEE 802.1CB
}

IP_PROTOS= {
    "ip":	        0,	# internet protocol, pseudo protocol number
    "hopopt":	    0,	# IPv6 Hop-by-Hop Option [RFC1883]
    "icmp":	        1,	# internet control message protocol
    "igmp":	        2,	# Internet Group Management
    "ggp":	        3,	# gateway-gateway protocol
    "ipencap":	    4,	# IP encapsulated in IP (officially ``IP'')
    "st":	        5,	# ST datagram mode
    "tcp":	        6,	# transmission control protocol
    "egp":	        8,	# exterior gateway protocol
    "igp":	        9,	# any private interior gateway (Cisco)
    "pup":	        12,	# PARC universal packet protocol
    "udp":	        17,	# user datagram protocol
    "hmp":	        20,	# host monitoring protocol
    "xns-idp":	    22,	# Xerox NS IDP
    "rdp":	        27,	# "reliable datagram" protocol
    "iso-tp4":	    29,	# ISO Transport Protocol class 4 [RFC905]
    "dccp":	        33,	# Datagram Congestion Control Prot. [RFC4340]
    "xtp":	        36,	# Xpress Transfer Protocol
    "ddp":	        37,	# Datagram Delivery Protocol
    "idpr-cmtp":    38,	# IDPR Control Message Transport
    "ip6":	        41,	# Internet Protocol, version 6
    "ipv6":	        41,	# Internet Protocol, version 6
    "ipv6-route":   43,	# Routing Header for IPv6
    "ipv6-frag":    44,	# Fragment Header for IPv6
    "idrp":	        45,	# Inter-Domain Routing Protocol
    "rsvp":	        46,	# Reservation Protocol
    "gre":      	47,	# General Routing Encapsulation
    "esp":      	50,	# Encap Security Payload [RFC2406]
    "ah":       	51,	# Authentication Header [RFC2402]
    "skip":     	57,	# SKIP
    "ipv6-icmp":    58,	# ICMP for IPv6
    "ipv6-nonxt":   59,	# No Next Header for IPv6
    "ipv6-opts":    60,	# Destination Options for IPv6
    "rspf":     	73,	# Radio Shortest Path First (officially CPHB)
    "vmtp":     	81,	# Versatile Message Transport
    "eigrp":        88,	# Enhanced Interior Routing Protocol (Cisco)
    "ospf":     	89,	# Open Shortest Path First IGP
    "ax.25":        93,	# AX.25 frames
    "ipip":     	94,	# IP-within-IP Encapsulation Protocol
    "etherip":      97,	# Ethernet-within-IP Encapsulation [RFC3378]
    "encap":        98,	# Yet Another IP encapsulation [RFC1241]
    "pim":      	103,	# Protocol Independent Multicast
    "ipcomp":       108,	# IP Payload Compression Protocol
    "vrrp":     	112,	# Virtual Router Redundancy Protocol [RFC5798]
    "l2tp":     	115,	# Layer Two Tunneling Protocol [RFC2661]
    "isis":     	124,	# IS-IS over IPv4
    "sctp":     	132,	# Stream Control Transmission Protocol
    "fc":       	133,	# Fibre Channel
    "mobility-header": 135, # Mobility Support for IPv6 [RFC3775]
    "udplite":      136,	# UDP-Lite [RFC3828]
    "mpls-in-ip":   137,	# MPLS-in-IP [RFC4023]
    "manet":        138,	# MANET Protocols [RFC5498]
    "hip":      	139,	# Host Identity Protocol
    "shim6":        140,	# Shim6 Protocol [RFC5533]
    "wesp":     	141,	# Wrapped Encapsulating Security Payload
    "rohc":     	142,	# Robust Header Compression
    "ethernet":     143,	# Ethernet encapsulation for SRv6 [RFC8986]
    # The following entries have not been assigned by IANA but are used
    # internally by the Linux kernel.
    "mptcp":        262,	# Multipath TCP connection
}
