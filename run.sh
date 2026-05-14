#!/bin/bash
set -u

PIN_ROOT="${PIN_ROOT:-/opt/pin}"

make clean
make

printf "%4096s" | tr ' ' 'X' > init.txt
pin -log_inline -t obj-intel64/tainttool.so -i init.txt -- ./NLQBox -i init.txt
./NLQBox -i input_secret.txt

