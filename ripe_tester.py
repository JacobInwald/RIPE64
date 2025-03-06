#!/usr/bin/python
# Updated version of program developed by Hubert ROSIER
# to assist the automated testing using the 64b port of the RIPE evaluation tool
#
# RIPE was originally developed by John Wilander (@johnwilander)
# and was debugged and extended by Nick Nikiforakis (@nicknikiforakis)
#
# Released under the MIT license (see file named LICENSE)
#
# The original program is part the paper titled
# RIPE: Runtime Intrusion Prevention Evaluator
# Authored by: John Wilander, Nick Nikiforakis, Yves Younan,
#              Mariam Kamkar and Wouter Joosen
# Published in the proceedings of ACSAC 2011, Orlando, Florida
#
# Please cite accordingly.

import os
import sys
import argparse

# Initialise default values
locations = ["stack","heap","bss","data"]
code_ptr = [
 "ret","baseptr",
 "funcptrstackvar", "funcptrstackparam",
 "funcptrheap", "funcptrbss", "funcptrdata",
 "structfuncptrstack", "structfuncptrheap",
 "structfuncptrbss", "structfuncptrdata",
 "longjmpstackvar", "longjmpstackparam",
 "longjmpheap", "longjmpbss", "longjmpdata"
]
attacks = [
 # "nonop","simplenop",
 "simplenopequival", "r2libc", "rop"]
funcs = [
    "memcpy", "strcpy", "strncpy", "sprintf", "snprintf",
    "strcat", "strncat", "sscanf", "fscanf", "homebrew"
  ]

# Arg Defaults
compilers = ["gcc", "clang"]
techniques = ["direct", "indirect"]
repeat_times = 0
results = {}
print_OK = True
print_SOME = True
print_FAIL = True
summary_format = "bash"


# Colored text
def colored_string(string, color, size=0):
    padding = ' '*(size-len(string)) if size else ''
    return color+string+'\033[0m'+padding
def red(string, size=0):
    return colored_string(string, '\033[91m', size)
def green(string, size=0):
    return colored_string(string, '\033[92m', size)
def orange(string, size=0):
    return colored_string(string, '\033[93m', size)
def blue(string, size=0):
    return colored_string(string, '\033[94m', size)
def bold(string, size=0):
    return colored_string(string, '\033[1m', size)
def underline(string, size=0):
    return colored_string(string, '\033[4m', size)

def analyze_log(log_entry, additional_info):
  if log_entry.find("jump buffer is between") != -1:
    additional_info += [orange('SpecialPayload')]

  if log_entry.find("Overflow pointer contains terminating char") != -1:
    additional_info += [orange("TermCharInOverflowPtr")]

  # Terminating chars in middle of the payload
  if log_entry.find("in the middle") != -1:
    additional_info += [orange('TermCharInPayload')]

  if log_entry.find("Unknown choice of") != -1:
    additional_info += [red('UnknownChoice')]

  if log_entry.find("Could not build payload") != -1:
    additional_info += [red('BuildPayloadFailed')]

  if log_entry.find("find_gadget") != -1:
    additional_info += [red('FindGadgetFail')]

  if log_entry.find("Unable to allocate heap") != -1:
    additional_info += [red('HeapAlloc')]

  if log_entry.find("the wrong order") != -1:
    additional_info += [red('HeapAllocOrder')]

  if log_entry.find("Target address is lower") != -1:
    additional_info += [red('Underflow')]

  # Defenses log
  if log_entry.find("AddressSanitizer") != -1:
    additional_info += [red('ASAN')]

  return additional_info

def analyze_log2(additional_info):
  i = 0
  while i < repeat_times:
    i += 1
    log_entry2 = open("/tmp/ripe_log2"+str(i),'r').read()
    if log_entry2.find("Segmentation fault") != -1:
      additional_info += [red('SEGFAULT')]
    elif log_entry2.find("Bus error") != -1:
      additional_info += [red('BUSERROR')]
    elif log_entry2.find("Illegal instruction") != -1:
      additional_info += [red('SIGILL')]
    # elif log_entry2.find("I/O error") != -1:
    # it is a 'normal' error when no shell has been spawned

  return additional_info


parser = argparse.ArgumentParser(
                    prog='RIPE64',
                    description='''A testbed for memory exploits in C.
                    Most recent version updated by Jacob Inwald, to add in CET emulation support and clean up python file.
                    Updated version of program developed by Hubert ROSIER to assist the automated testing using the 64b port of the RIPE evaluation tool. 
                    RIPE was originally developed by John Wilander (@johnwilander) and was debugged and extended by Nick Nikiforakis (@nicknikiforakis)''',
                    epilog='May your exploiting prove RIPE!')

parser.add_argument('-n', '--number', 
                    required=True,
                    type=int,
                    help='number of times to run each test')
parser.add_argument('-t', '--techniques',
                    default='both',
                    required=True, 
                    type=str,
                    choices=['direct', 'indirect', 'both'],
                    help='techniques to use, default is both')
parser.add_argument('-c', '--compiler',
                    default='both',
                    required=False,
                    type=str,
                    choices=['gcc', 'clang', 'both'],
                    help='compiler to test, default is both')
parser.add_argument('-f', '--format',
                    default='bash',
                    required=False,
                    type=str,
                    choices=['bash', 'latex'],
                    help='format of output table, default is bash')
parser.add_argument('-s', '--summary',
                    default='111',
                    required=False,
                    type=str,
                    choices=['000', '001', '010', '011', '100', '101', '110', '111'],
                    help='specifies content in summary, each number flips in order printing some, ok and then fail cases, by default 111 so all is enabled')
parser.add_argument('--cet', 
                    default='N', 
                    required=False,
                    type=str,
                    choices=['N', 'E', 'H'],
                    help='specifies whether to use CET, N means no CET, E means emulated CET using Intels SDE, and H means hardware enabled CET')
args = parser.parse_args()


# Parse arguments
repeat_times = args.number
summary_format = args.format
compilers = compilers if args.compiler == 'both' else [args.compiler]
techniques = techniques if args.techniques == 'both' else [args.techniques]
print_SOME = bool(args.summary[0])
print_OK = bool(args.summary[1])
print_FAIL = bool(args.summary[2])

# Add in command prepends to allow cet
emulate_cet = True
cet_prepend = ""
if args.cet == 'H':
    cet_prepend = "GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK "
elif args.cet == 'E': # TODO: add check for sde64 in path
    cet_prepend = "sde64 -cet -- "

cmd = cet_prepend + "$(pwd)/build/%s_attack_gen "


if not os.path.exists("/tmp/ripe-eval"):
  os.system("mkdir /tmp/ripe-eval")


for compiler in compilers:
  total = {'ok': 0, 'fail': 0, 'some': 0, 'np': 0}

  for tech in techniques:
    for loc in locations:
      for ptr in code_ptr:
        for attack in attacks:
          for func in funcs:
            i = 0
            s_attempts = 0
            attack_possible = 1
            parameters_str = "-t %8s -l %5s -c %18s -i %16s -f %8s" % (tech,loc,ptr,attack,func)
            
            additional_info = []
            for i in range(1, repeat_times+1, 1):
              
                # Command Setup
              os.system("rm /tmp/ripe_log")
              sys.stdout.write('... Running %s ...\r' % parameters_str)
              sys.stdout.flush()
              os.system("echo  %s >> /tmp/ripe_log" % parameters_str)
              
              cmdline = f"(echo \"touch /tmp/ripe-eval/f_xxxx\" | {(cmd % compiler)} {parameters_str} >> /tmp/ripe_log 2>&1) 2> /tmp/ripe_log2{i}"
              os.system(cmdline)
              
              # Check ouput
              log_entry = open("/tmp/ripe_log","r").read()
              
              if log_entry.find("Impossible") != -1:
                attack_possible = 0
                break  #Not possible once, not possible always

              additional_info = analyze_log(log_entry, additional_info)

              if os.path.exists("/tmp/ripe-eval/f_xxxx"):
                s_attempts += 1
                os.system("rm /tmp/ripe-eval/f_xxxx")
            
            # Finish attack checking
            if attack_possible == 0:
              total['np'] += 1
              continue

            # SUCCESS
            if s_attempts == repeat_times:
              if print_OK:
                print("%5s %s %s (%s/%s) %s" % (compiler,parameters_str,
                    green("OK", 4),
                    s_attempts,repeat_times,
                    ' '.join(set(additional_info))))
              total['ok'] += 1

            # FAIL
            elif s_attempts == 0:
              additional_info = analyze_log2(additional_info)
              if print_FAIL:
                print("%5s %s %6s (%s/%s) %s" % (compiler, parameters_str,
                     red("FAIL", 4),
                     s_attempts, repeat_times,
                     ' '.join(set(additional_info))))
              total['fail'] += 1

            # SOME
            else:
              if print_SOME:
                additional_info = analyze_log2(additional_info)
                print("%5s %s %6s (%s/%s) %s" % (compiler,parameters_str,
                    orange("SOME", 4),
                    s_attempts,repeat_times,
                    ' '.join(set(additional_info))))
              total['some'] += 1

  results[compiler] = total


total_attacks = sum(v for _, v in results[compilers[0]])


if "bash" in summary_format:
  for compiler in results:
    print("\n"+bold("||Summary "+compiler+"||"))
    total_attacks = results[compiler]["total_ok"] + results[compiler]["total_some"] + results[compiler]["total_fail"]
    print("OK: %s SOME: %s FAIL: %s NP: %s Total Attacks: %s\n\n"% (
      results[compiler]["total_ok"], results[compiler]["total_some"], results[compiler]["total_fail"],
      results[compiler]["total_np"], total_attacks))


if "latex" in summary_format:
  print("\\begin{tabular}{|c|c|c|c|}\\hline\n"
    "\\thead{Setup} & \\thead{Functional \\\\ attacks} & \\thead{Partly functional \\\\ attacks} & \\thead{Nonfunctional \\\\ attacks}\\\\\\hline\\hline\n")
  for compiler in results:
    print(" (%s) & %s (%s\\%%) & %s (%s\\%%) & %s (%s\\%%) \\\\ \\hline\n"% (
      compiler,
      results[compiler]["total_ok"], int(round((100.0*results[compiler]["total_ok"])/ total_attacks)),
      results[compiler]["total_some"], int(round((100.0*results[compiler]["total_some"])/ total_attacks)),
      results[compiler]["total_fail"], int(round((100.0*results[compiler]["total_fail"])/ total_attacks))
      ))
  print("\\end{tabular}\n")



