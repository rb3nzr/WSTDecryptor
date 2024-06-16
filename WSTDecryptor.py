#!/usr/bin/env python3

import argparse
import os
from core.Config import banner, base_path
from core.Extractor import ShellSearcher
from webshells.Weevely3 import Weevely3Decryptor 
from webshells.SharPyShell import SharPyShellDecryptor
from webshells.Godzilla import GodzillaDecryptor

main_help_text = """
Examples:
        python WSTDecryptor.py [webshell type] -h
        python WSTDecryptor.py sharpyshell -p sample.pcapng -i X.X.X.X -k <key> --extract
        python WSTDecryptor.py findshell -p sample.pcapng
"""

def add_common_arguments(generate_parser):
    generate_parser.add_argument(
        '-p', '--pcap', type=str, help='the .pcap(ng) to parse', required=True)
    generate_parser.add_argument(
        '-i', '--ip', type=str, help='the ip associated with the traffic', required=True)

def find_shell_parser(subparsers):
    generate_parser = subparsers.add_parser(
        'findshell', formatter_class=argparse.RawTextHelpFormatter,
        usage = 'WSTDecryptor.py findshell -p sample.pcap(ng)',
        help = 'Looks for keys and webshells in the capture file. \
                \nIf any webshells are located then the payload is extracted to output/ex_webshells.\n'
    )
    generate_parser.add_argument(
        '-p', '--pcap', type=str, help='the .pcap(ng) to parse', required=True)
    generate_parser.set_defaults(mode='findshell')

def weevely3_parser(subparsers):
    generate_parser = subparsers.add_parser(
        'weevely3', formatter_class=argparse.RawTextHelpFormatter,
        usage = 'WSTDecryptor.py weevely3 -p sample.pcap(ng) -i x.x.x.x -w sample.php',
        help = 'Extract and decrypt traffic sent to a Weevely3 webshell',
    )
    add_common_arguments(generate_parser)
    generate_parser.add_argument(
        '-w', '--webshell', type=str, help='the webshell file', required=True)
    generate_parser.set_defaults(mode='weevely3')

def sharpyshell_parser(subparsers):
    generate_parser = subparsers.add_parser(
        'sharpyshell', formatter_class=argparse.RawTextHelpFormatter,
        usage = 'WSTDecryptor.py sharpyshell -p sample.pcap(ng) -i x.x.x.x -k "<KEY>" --extract',
        help = 'Extract and decrypt traffic sent to a SharPyShell webshell',
    )
    add_common_arguments(generate_parser)
    generate_parser.add_argument(
        '-k', '--key', type=str, help='the encryption key used in the webshell', required=True)
    generate_parser.add_argument(
        '-x', '--extract', action="store_true", 
        help='Use this flag to auto run the module/shellcode extraction script at the end. \
              \nIf the output file is large, this might take a minute or two.', 
        required=False)
    generate_parser.set_defaults(mode='sharpyshell')

def godzilla_parser(subparsers):
    generate_parser = subparsers.add_parser(
        'godzilla', formatter_class=argparse.RawTextHelpFormatter,
        usage = 'WSTDecryptor.py godzilla -p sample.pcap(ng) -i x.x.x.x -k "<KEY>" [--raw]',
        help = 'Extract and decrypt traffic sent to a Godzilla webshell',
    )
    add_common_arguments(generate_parser)
    generate_parser.add_argument(
        '-k', '--key', type=str, help='The encryption key used in the webshell', required=True)
    generate_parser.add_argument(
        '-r', '--raw', action='store_true', help='Set this flag if payload data is raw', required=False)
    generate_parser.set_defaults(mode='godzilla')

if __name__ == '__main__':
    print(banner)
    parser = argparse.ArgumentParser(
        prog='WSTDecryptor', formatter_class=argparse.RawTextHelpFormatter, epilog=main_help_text
    )
    subparsers = parser.add_subparsers()
    find_shell_parser(subparsers)
    weevely3_parser(subparsers)
    sharpyshell_parser(subparsers)
    godzilla_parser(subparsers)
    args = parser.parse_args()

    if hasattr(args, 'mode'):
        if args.mode == 'findshell':
            shellsearcher = ShellSearcher(args.pcap)
            shellsearcher.run()
        if args.mode == 'weevely3':
            os.makedirs(os.path.join(base_path, "output"), exist_ok=True)
            weev_decryptor = Weevely3Decryptor(args.webshell, args.pcap, args.ip)  
            weev_decryptor.run()
        elif args.mode == 'sharpyshell':
            os.makedirs(os.path.join(base_path, "output"), exist_ok=True)
            sp_decryptor = SharPyShellDecryptor(args.pcap, args.ip, args.key, args.extract)
            sp_decryptor.run()
        elif args.mode == 'godzilla':
            os.makedirs(os.path.join(base_path, "output"), exist_ok=True)
            god_decryptor = GodzillaDecryptor(args.pcap, args.ip, args.key, args.raw)
            god_decryptor.run()
    else:
        parser.print_help()

        






