#!/bin/bash

gcc -g crumbwrap.c -Wall -O2 -o crumbwrap || exit -1
gcc -shared crumbwrap_hooks.c -lc -ldl -fPIC -Wall -O2 -o crumbwrap_hooks.so || exit -1
