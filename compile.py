#!/usr/bin/python3

'''Generic compiler frontend'''

import sys
from argparse import ArgumentParser
import json
import pcap_parser
from code_objects import finalize, ProgramEncoder
import code_objects
import bpf_objects
import u32_objects

HELPERS = {
    "cbpf":bpf_objects.dispatcher,
    "u32":u32_objects.dispatcher,
}


def main():
    '''Parse a pcap expression and compile it into
    bpf
    '''
    aparser = ArgumentParser(description=main.__doc__)
    aparser.add_argument(
       '--expression',
        help='pcap expression',
        type=str
        )
    aparser.add_argument(
       '--debug',
        help='debug level',
        type=int,
        default=0
        )
    aparser.add_argument(
       '--output',
        help='output file, if absent - stdout',
        type=str
        )
    aparser.add_argument(
       '--generators',
        help='code generators cbpf, etc',
        action="append",
        type=str
        )
    aparser.add_argument(
       '--format',
        help='output format asm, iptables, binary',
        type=str,
        default="asm"
        )
    args = vars(aparser.parse_args())

    try:
        generators = args["generators"]
    except KeyError:
        generators = ["cbpf"]

    if generators is None:
        generators = ["cbpf"]

    parsed = finalize(pcap_parser.PARSER.parse(args["expression"]))

    if args["format"] in ["iptables", "u32"]:
        parsed.drop_type(code_objects.ProgL2)
    

    if args["debug"] > 0:
        sys.stderr.write(json.dumps(parsed, cls=ProgramEncoder, indent=4))
        sys.stderr.write("\n")

    for generator in generators:
        parsed.add_helper(HELPERS[generator])

    parsed.compile(bpf_objects.CBPFCompilerState()) # FIXME - make generic

    try:
        out = open(args["output"],"+w",encoding="ascii")
    except (KeyError, TypeError):
        out = sys.stdout


    if args["debug"] > 0:
        for helper in parsed.helpers:
            out.write(helper.dump_code(args["format"],["lines"]))

    
    parsed.resolve_refs()

    for helper in parsed.helpers:
        out.write(helper.dump_code(args["format"],["lines"]))

    if out != sys.stdout:
        out.close()


if __name__ == "__main__":
    main()
