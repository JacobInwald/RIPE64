#!/bin/python

import os, argparse

# Defaults
compiler = 'gcc'

stkcan = '-fstack-protector-strong'
dforti = '-DFORTIFY_SOURCE=3 -O2'
stkcla = '-fstack-clash-protection'
fcfpro = '-fcf-protection=full'
mshstk = '-fcf-protection=return'

parser = argparse.ArgumentParser(
                    prog='RIPE64 - Flag Tester',
                    description='''A python script to test specific combinations of flags with the RIPE64 tester.''', 
                    epilog='')
parser.add_argument('-s', '--stkcan',
                    action='store_true',
                    help='Adds stack canaries to test list')
parser.add_argument('-c', '--stkcla',
                    action='store_true',
                    help='Adds stack clash protection to test list')
parser.add_argument('-d', '--dforti',
                    action='store_true',
                    help='Adds DFORTIFY_SOURCE to test list')
parser.add_argument('-f', '--fcfpro',
                    action='store_true',
                    help='Adds Intels CET to test list')
parser.add_argument('-m', '--mshstk',
                    action='store_true',
                    help='Adds Intels Shadow Stack to test list')
parser.add_argument('--enable_hardware_cet',
                    action='store_true',
                    help='Enables hardware support for CET, may turn off IBT features')
args = parser.parse_args()

HARDEN_FLAGS = ''
HARDEN_FLAGS += stkcan if args.stkcan else ''
HARDEN_FLAGS += ' ' + stkcla if args.stkcla else ''
HARDEN_FLAGS += ' ' + dforti if args.dforti else ''
HARDEN_FLAGS += ' ' + fcfpro if args.fcfpro else ''
HARDEN_FLAGS += ' ' + mshstk if args.mshstk else ''
os.environ['HARDEN_FLAGS'] = HARDEN_FLAGS

fp = 'out-'
fp += 'stkcan-' if args.stkcan else ''
fp += 'stkcla-' if args.stkcla else ''
fp += 'dforti-' if args.dforti else ''
fp += 'fcfpro-' if args.fcfpro else ''
fp += 'mshstk-' if args.mshstk else ''
fp = fp[:-1]

cet = 'N'
if args.fcfpro or args.mshstk:
    cet = 'H' if args.enable_hardware_cet else 'E'

os.makedirs('data', exist_ok=True)
os.makedirs('build', exist_ok=True)
os.system('make clean')
os.system('make build/gcc_attack_gen')
os.system(f'./ripe_tester.py -t both -n 3 -c {compiler} -f latex --cet {cet} > data/{fp} ')
