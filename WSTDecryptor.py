#!/usr/bin/env python3

import argparse
import os
from core.Config import *
from core.Extractor import ShellSearcher
from webshells.Weevely3 import Weevely3Decryptor 
from webshells.SharPyShell import SharPyShellDecryptor
from webshells.Godzilla import GodzillaDecryptor

main_help_text = f"""
{red}Examples:
        {magenta}python WSTDecryptor.py [webshell type] -h
        {magenta}python WSTDecryptor.py sharpyshell -p sample.pcapng -i X.X.X.X -k <key> --extract
        {magenta}python WSTDecryptor.py findshell -p sample.pcapng{end}
"""

def add_common_arguments(generate_parser):
    generate_parser.add_argument(
        '-p', '--pcap', type=str, help=f'{blue}the .pcap(ng) to parse{end}', required=True)
    generate_parser.add_argument(
        '-i', '--ip', type=str, help=f'{blue}the IP associated with the traffic{end}', required=True)
    generate_parser.add_argument(
        '-pt', '--port', type=int, help=f'{white}default 80{end}', default=80, required=False)

def find_shell_parser(subparsers):
    generate_parser = subparsers.add_parser(
        'findshell', formatter_class=argparse.RawTextHelpFormatter,
        usage = f'{magenta}WSTDecryptor.py findshell -p sample.pcap(ng){end}',
        help = f'{cyan}Looks for keys and webshells in the capture file. \
                \nIf any webshells are located then the payload is extracted to output/ex_webshells.{end}\n'
    )
    generate_parser.add_argument(
        '-p', '--pcap', type=str, help=f'{blue}the .pcap(ng) to parse{end}', required=True)
    generate_parser.set_defaults(mode='findshell')

def weevely3_parser(subparsers):
    generate_parser = subparsers.add_parser(
        'weevely3', formatter_class=argparse.RawTextHelpFormatter,
        usage = f'{magenta}WSTDecryptor.py weevely3 -p sample.pcap(ng) -i x.x.x.x -w sample.php{end}',
        help = f'{cyan}Extract and decrypt traffic sent to a Weevely3 webshell{end}',
    )
    add_common_arguments(generate_parser)
    generate_parser.add_argument(
        '-w', '--webshell', type=str, help=f'{blue}the webshell file{end}', required=True)
    generate_parser.set_defaults(mode='weevely3')

def sharpyshell_parser(subparsers):
    generate_parser = subparsers.add_parser(
        'sharpyshell', formatter_class=argparse.RawTextHelpFormatter,
        usage = f'{magenta}WSTDecryptor.py sharpyshell -p sample.pcap(ng) -i x.x.x.x -k "<KEY>" --extract{end}',
        help = f'{cyan}Extract and decrypt traffic sent to a SharPyShell webshell{end}',
    )
    add_common_arguments(generate_parser)
    generate_parser.add_argument(
        '-k', '--key', type=str, help=f'{blue}the encryption key used in the webshell{end}', required=True)
    generate_parser.add_argument(
        '-x', '--extract', action="store_true", 
        help=f'{blue}Use this flag to auto run the module/shellcode extraction script at the end. \
              \nIf the output file is large, this might take a minute or two.{end}', 
        required=False)
    generate_parser.set_defaults(mode='sharpyshell')

def godzilla_parser(subparsers):
    generate_parser = subparsers.add_parser(
        'godzilla', formatter_class=argparse.RawTextHelpFormatter,
        usage = f'{magenta}WSTDecryptor.py godzilla -p sample.pcap(ng) -i x.x.x.x -k "<KEY>" [--raw]{end}',
        help = f'{cyan}Extract and decrypt traffic sent to a Godzilla webshell{end}',
    )
    add_common_arguments(generate_parser)
    generate_parser.add_argument(
        '-k', '--key', type=str, help=f'{blue}The encryption key used in the webshell{end}', required=True)
    generate_parser.add_argument(
        '-r', '--raw', action='store_true', help=f'{blue}Set this flag if payload data is raw{end}', required=False)
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
            weev_decryptor = Weevely3Decryptor(args.webshell, args.pcap, args.ip, args.port)  
            weev_decryptor.run()
        elif args.mode == 'sharpyshell':
            os.makedirs(os.path.join(base_path, "output"), exist_ok=True)
            sp_decryptor = SharPyShellDecryptor(args.pcap, args.ip, args.port, args.key, args.extract)
            sp_decryptor.run()
        elif args.mode == 'godzilla':
            os.makedirs(os.path.join(base_path, "output"), exist_ok=True)
            god_decryptor = GodzillaDecryptor(args.pcap, args.ip, args.port, args.key, args.raw)
            god_decryptor.run()
    else:
        parser.print_help()


        






