#!/usr/bin/python3

from argparse import ArgumentParser
import parser
from parsed_tree import LEFT, RIGHT, OP, OBJ, QUALS, OBJTYPE, PROTO
from code_objects import finalize


def main():
    '''Parse a pcap expression and compile it into
    bpf
    '''
    aparser = ArgumentParser(description=main.__doc__)
    aparser.add_argument(
       '--expr',
        help='pcap expression',
        type=str
        )
    
    aparser.add_argument(
       '--format',
        help='output format',
        type=str,
        default="cbpf"
        )
    args = vars(aparser.parse_args())

    parsed = finalize(parser.PARSER.parse(args["expr"]))

    parsed.compile()

    counter = 0
    for inst in parsed.get_code():
        print("{} {}".format(counter, inst))
        counter += 1

    parsed.resolve_frag_refs()

    counter = 0
    for inst in parsed.get_code():
        print("{} {}".format(counter, inst))
        counter += 1

    parsed.resolve_refs()

    counter = 0
    for inst in parsed.get_code():
        print("{} {}".format(counter, inst))
        counter += 1

if __name__ == "__main__":
    main()

