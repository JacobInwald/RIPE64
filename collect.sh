#!/bin/sh

# ./flag_tester.py 
# ./flag_tester.py -s
# ./flag_tester.py -d
./flag_tester.py -m --enable_hardware_cet 
./flag_tester.py -sd
./flag_tester.py -sdm --enable_hardware_cet

./flag_tester.py -f
./flag_tester.py -sdf
