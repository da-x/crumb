#!/bin/bash

# Just for clarification, this is how we would have built this demo-project if we didn't have a build system.

gcc -O2 bigo.c -o bigo.o -c
gcc -O2 bigo2.c -o bigo2.o -c
python generator.py auto_generated.h
gcc -O2 program.c -o program.o -c
gcc bigo.o bigo2.o program.o -o program
