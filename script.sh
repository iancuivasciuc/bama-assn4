#!/bin/bash
set -euo pipefail

PIN_ROOT="${PIN_ROOT:-/opt/pin}"

make clean
make

printf "%4096s" | tr ' ' 'X' > init.txt
pin -t obj-intel64/tainttool.so -i init.txt -- ./NLQBox -i init.txt

