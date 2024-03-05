#!/usr/bin/python3

'''Generic compiler frontend'''

import sys
import json
from argparse import ArgumentParser
import subprocess
from ipaddress import IPv6Address, IPv6Network, ip_address, ip_network
import code_objects
import bpf_objects
import u32_objects
from policy import PolicyEntry, FirewallPolicy

HELPERS = [
    ("u32", u32_objects.dispatcher),
    ("cbpf", bpf_objects.dispatcher),
]

ACTION_MAP = {
    "Deny": "DROP",
    "Allow": "ACCEPT"
}

def is_v6(address):
    '''Check if an address is v6'''
    try:
        addr = ip_address(address)
        if isinstance(addr, IPv6Address):
            return True
    except ValueError:
        # we let it raise a value error in this case
        addr = ip_network(address)

    return isinstance(addr, IPv6Network)



def process_icmp(p_cfg, cidr):
    '''Process ICMP'''
    pcap_expr = []
    try:
        #pylint: disable=consider-using-f-string
        pcap_expr.append("icmp[icmptype] == {}".format(p_cfg["icmp"]["icmpType"]))
    except KeyError:
        pass

    try:
        #pylint: disable=consider-using-f-string
        pcap_expr.append("icmp[icmpcode] == {}".format(p_cfg["icmp"]["icmpCode"]))
    except KeyError:
        pass

    if len(pcap_expr) == 0:
        raise ValueError("Failed to process firewall policy")

    if len(pcap_expr) == 1:
        #pylint: disable=consider-using-f-string
        return "src {} and {}".format(cidr, pcap_expr[0])

    #pylint: disable=consider-using-f-string
    return "src {} and {}".format(cidr, " and ".join(pcap_expr))

def process_icmp_v6(p_cfg, cidr):
    '''Process ICMP'''
    pcap_expr = []
    try:
        #pylint: disable=consider-using-f-string
        pcap_expr.append("icmp6[icmptype] == {}".format(p_cfg["icmpv6"]["icmpType"]))
    except KeyError:
        pass

    try:
        #pylint: disable=consider-using-f-string
        pcap_expr.append("icmp6[icmpcode] == {}".format(p_cfg["icmpv6"]["icmpCode"]))
    except KeyError:
        pass

    if len(pcap_expr) == 0:
        raise ValueError("Failed to process firewall policy")

    if len(pcap_expr) == 1:
        #pylint: disable=consider-using-f-string
        return "src {} and {}".format(cidr, pcap_expr[0])

    #pylint: disable=consider-using-f-string
    return "src {} and {}".format(cidr, " and ".join(pcap_expr))


def process_proto(proto, p_cfg, cidr):
    '''Process TCP/UDP/SCTP'''
    pcap_expr = []

    #pylint: disable=consider-using-f-string
    if "-" in p_cfg[proto]["ports"]:
        pcap_expr.append("portrange {}".format(p_cfg[proto]["ports"]))
    else:
        pcap_expr.append("port {}".format(p_cfg[proto]["ports"]))
    if len(pcap_expr) == 0:
        raise ValueError("Failed to process firewall policy")

    #pylint: disable=consider-using-f-string
    return "src {} and {} dst {}".format(cidr, proto, pcap_expr[0])

def form_args(interface, rule, mode, options):
    '''Form iptables arguments'''

    res = ""

    u32_ok = False

    if rule.v6:
        iptables = "/sbin/ip6tables"
    else:
        iptables = "/sbin/iptables"

    if mode in ["u32", "auto"]:
        try:
            code = rule.dump_code("u32", "iptables", options)
            if len(code) > 0:
                res = f"{iptables} -A IFW -j {rule.action} -i {interface} -m u32  --u32 '{code}'"
                u32_ok = True
        except KeyError:
            pass

    if not u32_ok and mode in ["cbpf", "auto"]:
        try:
            code = rule.dump_code("cbpf", "iptables", options)
            if len(code) > 0:
                res = f"{iptables} -A IFW -j {rule.action} -i {interface} -m bpf --bpf '{code}'"
        except KeyError:
            pass

    return res

def dry_run_u32_apply_fn(interface, rule, options):
    '''Dry run function - print the rules which will be applied'''
    print(form_args(interface, rule, "u32", options))
    return True

def dry_run_cbpf_apply_fn(interface, rule, options):
    '''Dry run function - print the rules which will be applied'''
    print(form_args(interface, rule, "cbpf", options))
    return True

def iptables_u32_apply_fn(interface, rule, options):
    '''Apply via iptables'''
    try:
        subprocess.run(form_args(interface, rule, "u32", options), shell=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def iptables_cbpf_apply_fn(interface, rule, options):
    '''Apply via iptables'''
    try:
        subprocess.run(form_args(interface, rule, "cbpf", options), shell=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

FLUSH_DATA = [
    "/sbin/iptables -F IFW",
    "/sbin/ip6tables -F IFW",
]

PREAMBLE_DATA = [
    "/sbin/iptables -D INPUT -j IFW",
    "/sbin/iptables -X IFW",
    "/sbin/iptables -N IFW",
    "/sbin/iptables -I INPUT -j IFW",

    "/sbin/ip6tables -D INPUT -j IFW",
    "/sbin/ip6tables -X IFW",
    "/sbin/ip6tables -N IFW",
    "/sbin/ip6tables -I INPUT -j IFW",
]

CLOSURE_DATA = [
    "/sbin/iptables -A IFW -j RETURN",
    "/sbin/ip6tables -A IFW -j RETURN"
]

def dryrun_flush_fn():
    '''Apply via iptables'''
    for flush in FLUSH_DATA:
        print(flush)

def dryrun_preamble_fn():
    '''Apply via iptables'''
    for preamble in PREAMBLE_DATA:
        print(preamble)

def dryrun_closure_fn():
    '''Apply via iptables'''
    for closure in CLOSURE_DATA:
        print(closure)

def iptables_flush_fn():
    '''Apply via iptables'''
    for flush in FLUSH_DATA:
        subprocess.run(flush, shell=True, check=False)

def iptables_preamble_fn():
    '''Apply via iptables'''
    for preamble in PREAMBLE_DATA:
        subprocess.run(preamble, shell=True, check=False)

def iptables_closure_fn():
    '''Apply via iptables'''
    for closure in CLOSURE_DATA:
        subprocess.run(closure, shell=True, check=False)


PROTO_MAP = {
    "ICMP":process_icmp,
    "ICMPv6":process_icmp_v6,
    "TCP":lambda p_cfg, cidr : process_proto("tcp", p_cfg, cidr),
    "UDP":lambda p_cfg, cidr : process_proto("udp", p_cfg, cidr),
    "SCTP":lambda p_cfg, cidr : process_proto("sctp", p_cfg, cidr),
}

ACTIVATORS = {
    "dryrun-cbpf":dry_run_cbpf_apply_fn,
    "dryrun-u32":dry_run_u32_apply_fn,
    "iptables-cbpf":iptables_cbpf_apply_fn,
    "iptables-u32":iptables_u32_apply_fn
}

PREAMBLES = {
    "dryrun":dryrun_preamble_fn,
    "iptables":iptables_preamble_fn,
}

FLUSHES = {
    "dryrun":dryrun_flush_fn,
    "iptables":iptables_flush_fn,
}

CLOSURES = {
    "dryrun":dryrun_closure_fn,
    "iptables":iptables_closure_fn,
}

def makefilter_rule(p_cfg, cidr):
    '''Generate an actual filter rule
       CIDR encodes the ip version of the rule required
       '''
    return PROTO_MAP[p_cfg["protocol"]](p_cfg, cidr)

class IngressFirewallPolicy(FirewallPolicy):
    '''Class representing an ingress firewall policy'''
    def __init__(self, interface, policy, options=None):
        super().__init__()
        self.policy = policy
        self.in_hardware = []
        self.interface = interface
        self.options = options

    def generate_pcap(self):
        '''Convert policy to the same form as pcap output'''
        for item in self.policy:
            for cidr in item["sourceCIDRs"]:
                for rule in item["rules"]:
                    self.add_entry(
                        PolicyEntry(
                            ACTION_MAP[rule["action"]],
                            makefilter_rule(rule["protocolConfig"], cidr),
                            order=rule["order"],
                            model=rule,
                            v6=is_v6(cidr)
                        )
                    )

    def compile_pcap(self):
        '''Compile the actual rules'''
        for rule in self.rules:
            #pylint: disable=unused-variable
            rule.parse()
            rule.drop_type(code_objects.ProgL2)
            for (name, helper) in HELPERS:
                # we drop L2 for now. Both u32 offload and netfilter work
                # with L3 frames omitting the L2 header.
                # In fact, according to the comments in the driver code, U32 L2 not supported
                rule.add_helper(helper)
            rule.compile()

    def apply_to_hardware(self, apply_fn):
        '''Apply Policy'''
        while len(self.rules) > 0:
            if apply_fn(self.interface, self.rules[0], self.options):
                self.in_hardware.append(self.rules.pop(0))
            else:
                break

    def dump_rules(self, software=True):
        '''Dump all rules that have not been applied'''
        result = []
        if software:
            for rule in self.rules:
                result.append(rule.model)
        else:
            for rule in self.in_hardware:
                result.append(rule.model)

        return result

def main():
    '''Load an ingress firewall ruleset'''

    model = json.load(sys.stdin)

    aparser = ArgumentParser(description=main.__doc__)
    aparser.add_argument(
       '--mode',
        help='mode of operation dryrun, iptables',
        type=str,
        default="dryrun"
    )
    aparser.add_argument(
       '--backend',
        help='backend - u32, bpf',
        type=str,
        default="u32"
    )
    aparser.add_argument(
       '--debug',
        help='debug',
        action='store_true'
    )
    aparser.add_argument(
       '--flush',
        help='flush iptables',
        action='store_true'
    )
    aparser.add_argument(
       '--append',
        help='append iptables',
        action='store_true',
        default='false'
    )
    aparser.add_argument(
       '--close',
        help='close IFW chain in iptables',
        action='store_true',
        default='false'
    )

    args = vars(aparser.parse_args())

    if (args["flush"]):
        FLUSHES["{}".format(args["mode"])]()

    if (not args["append"]):
        PREAMBLES["{}".format(args["mode"])]()
    for (interface, policy) in model.items():
        ingress = IngressFirewallPolicy(interface, policy)
        ingress.generate_pcap()
        if args.get("debug"):
            for rule in ingress.rules:
                print(rule.pfilter)
        ingress.compile_pcap()
        if args.get("debug"):
            for rule in ingress.rules:
                for helper in rule.compiled.code.keys():
                    print(rule.compiled.get_code(helper))
        ingress.apply_to_hardware(ACTIVATORS["{}-{}".format(args["mode"], args["backend"])])

    ingress.apply_to_hardware(ACTIVATORS["{}-{}".format(args["mode"], args["backend"])])

    if (args["close"]):
        CLOSURES["{}".format(args["mode"])]()


if __name__ == "__main__":
    main()
