#!/usr/bin/python3

'''Generic compiler frontend'''

import sys
import json
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



PROTO_MAP = {
    "ICMP":process_icmp,
    "TCP":lambda p_cfg, cidr : process_proto("tcp", p_cfg, cidr),
    "UDP":lambda p_cfg, cidr : process_proto("udp", p_cfg, cidr),
    "SCTP":lambda p_cfg, cidr : process_proto("sctp", p_cfg, cidr),
}


def makefilter_rule(p_cfg, cidr):
    '''Generate an actual filter rule
       CIDR encodes the ip version of the rule required
       '''
    return PROTO_MAP[p_cfg["protocol"]](p_cfg, cidr)

class IngressFirewallPolicy(FirewallPolicy):
    '''Class representing an ingress firewall policy'''
    def __init__(self, policy):
        super().__init__()
        self.policy = policy
        self.in_hardware = []

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
                            model=rule
                        )
                    )

    def compile_pcap(self):
        '''Compile the actual rules'''
        for rule in self.rules:
            #pylint: disable=unused-variable
            for (name, helper) in HELPERS:
                # we drop L2 for now. Both u32 offload and netfilter work
                # with L3 frames omitting the L2 header.
                # In fact, according to the comments in the driver code, U32 L2 not supported
                rule.parse()
                rule.add_helper(helper)
                rule.drop_type(code_objects.ProgL2)
                rule.compile()

    def apply_to_hardware(self, apply_fn):
        '''Apply Policy'''
        while len(self.rules) > 0:
            if apply_fn(self.rules[0]):
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
    # TODO - add self/test execution
    policy = json.load(sys.stdin)

if __name__ == "__main__":
    main()
