#!/bin/bash

gcc -g crumb.c -Wall -O2 -o crumb || exit -1
gcc -shared crumbwrap.c -lc -ldl -fPIC -Wall -O2 -o crumbwrap.so || exit -1
