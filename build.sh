#!/bin/bash

gcc -shared crumbwrap.c -lc -ldl -fPIC -Wall -O2 -o crumbwrap.so