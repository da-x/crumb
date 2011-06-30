Crumb, experimental work
========================

Abstract
--------

The goal of crumb is dual:
1) Provide an infrastructure for automatic dependency detection in build systems,
   based on libc hooking (crumbwrap).
2) Provide an alternative build system altogther, named 'crumb', that relies on (1).

One of the big issues with the commonly used build systems is that each build system
is implementing its own language-specific dependencies scanning, for each one of the
major industry programming languages. This is a huge shortcoming, because when a
project gets bigger, custom-made and intermidary build outputs are integrated into
the build tree and dependency management on those custom made tools is never easy.
Missing out on dependencies can be hazardous to the final outcome of th build,
creating inconsistencies.

Crumb comes to change all that. The idea is to run a wrapper utility around the all
program invocations (compiler, linker, etc) participating in the build, and etect
their dependencies as it requests them.

The assumption that any compiler that compiles a file, is using standard libc calls
in order to follow any dependencies it finds. For example, say a.c is being compiled
by gcc and it includes a.h, which in turns includes b.h. If we hook the open() calls
in gcc, we would see 3 calls to open, and by using these hooks the build system can
track the dependencies of the compilation.

This scheme will also work with any build tool - say you wrote a Python script that
generates an header from an XML, and it also uses another file as a template for
the generated output. Then, in our build system - you wouldn't need to explicitly
specific those dependencies. By invoking the script via crumb, the build system
will automatically detect the target's dependency over the Python script, all the
Python imports that it does, the template file, the XML file, etc.

Implementation
--------------

crumb is an wrapper executable that uses LD_PRELOAD along with a shared library
in order to wrap libc system calls, and freeze processes that perform these
system calls until the revealed dependencies get satisfied. crumb communicates
with its hooks via UNIX-domain sockets, and it communicates with the build system
using a bi-directional pipe.

Foe example, here's a wrapping of gcc via crumb:

   crumbwrap gcc -c test/a.c -o test/a.o

It will emit the line:

   0:VFS:READ:ACCESS:/usr/bin/gcc

The reason is that gcc is being looked up in PATH by exec(). It will just wait
frozen until the invoker writes 'RELEASE 0'. Then, it will continue to the next
file:

   0:VFS:READ:ACCESS:test/a.c

The build system sees that the file exists. No problem, 'RELEASE 0'.

   0:VFS:READ:OPEN_RDONLY:test/a.h

Woha, test/a.h needs to be generated from test/a.xml. No problem, the build system
will recurse and generate test/a.xml, during which, gcc will remain happily halted.
Only then, it will write back 'RELEASE 0'.

Prototype and testing
---------------------

(relevent to commmit 6491ec24, later versions will work differently)

crumb.py is a prototype frontend that serves as a reference implementation for
the actual code of crumb. It uses the crumbwrap tool that was described above.
For testing it, I've added a demo project named 'arena1'.

The 'arena1' test program depends on 3 .o files, two of them take noticble time to
compile. The other depend on a C header and then indirectly depends on an
auto-generated header that is generated using a python script. The python
script also implicitly depends on an extra local Python module import, and on a
local text file.

All of these dependencies should be automatically detected by crumb.

To test crumb.py on a sample project, first build crumb:

   ./build.sh

   (it is not self-hosting yet :)

Then, run crumb.py on test/arena1:

   ./crumb.py -C test/arena1

crumb: [program]: executing: gcc bigo.o bigo2.o program.o -o program
crumb: [program]: invoking prefetch on bigo.o
crumb: [bigo.o]: executing: gcc -O2 -c bigo.c -o bigo.o
crumb: [program]: invoking prefetch on bigo2.o
crumb: [bigo2.o]: executing: gcc -O2 -c bigo2.c -o bigo2.o
crumb: [program]: invoking prefetch on program.o
crumb: [program.o]: executing: gcc -O2 -c program.c -o program.o
crumb: [program]: waiting for dep target bigo.o to be made
crumb: [bigo.o]: detected leaf dep: bigo.c
crumb: [bigo2.o]: detected leaf dep: bigo2.c
crumb: [program.o]: detected leaf dep: program.c
crumb: [program.o]: detected leaf dep: program.h
crumb: [program.o]: detected leaf dep: otherheader.h
crumb: [auto_generated.h]: executing: python generator.py auto_generated.h
crumb: [auto_generated.h]: invoking prefetch on generator.py
crumb: [auto_generated.h]: leaf dep in prefetch: generator.py
crumb: [program.o]: waiting for dep target auto_generated.h to be made
crumb: [auto_generated.h]: detected leaf dep: generator.py
crumb: [auto_generated.h]: detected leaf dep: someimport.py
crumb: [auto_generated.h]: detected leaf dep: someimport.pyc
crumb: [auto_generated.h]: detected output: auto_generated.h
crumb: [auto_generated.h]: detected leaf dep: and-another-dep.txt
crumb: [auto_generated.h]: tool exited (status=0)
crumb: [program.o]: dep target auto_generated.h completed, proceeding
crumb: [program.o]: detected output: program.o
crumb: [program.o]: tool exited (status=0)
crumb: [bigo.o]: detected output: bigo.o
crumb: [bigo.o]: tool exited (status=0)
crumb: [program]: dep target bigo.o completed, proceeding
crumb: [program]: waiting for dep target bigo2.o to be made
crumb: [bigo2.o]: detected output: bigo2.o
crumb: [bigo2.o]: tool exited (status=0)
crumb: [program]: dep target bigo2.o completed, proceeding
crumb: [program]: dep target program.o done already, proceeding
crumb: [program]: detected output: program
crumb: [program]: dep target bigo.o done already, proceeding
crumb: [program]: dep target bigo2.o done already, proceeding
crumb: [program]: detected output: program
crumb: [program]: tool exited (status=0)


People
------

For more questions, you can contact me: dan at aloni.org.
