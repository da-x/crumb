Crumb, experimental work
========================

Abstract
--------

The goal is to provide an infrastructure for automatic dependency detection in
build systems, based on libc hooking. Instead of each build system implementing it's
own language-specific dependencies scanning, one of each major industry programming
languages, the idea is to run this utility while the compiler is running.

The assumption that any compiler that compiles a file, is using standard libc calls
in order to follow any dependencies it finds. For example, say a.c is being compiled
by gcc and it includes a.h, which in turns includes b.h. If we hook the open() calls
in gcc, we would see 3 calls to open, and by using these hooks the build system can
track the dependencies of the compilation.

This scheme will also work with any build tool - say you wrote a Python script that
generates an header from an XML, and it also uses another file as a template for
the generated output. Then, in our build system - you wouldn't need to explicitly
specific those dependencies. By invoking the script via Crumb, the build system
will automatically detect the target's dependency over the Python script, all the
Python imports that it does, the template file, the XML file, etc.

Implementation
--------------

Crumb is an wrapper executable that uses LD_PRELOAD along with a shared library
in order to wrap libc system calls, and freeze processes that perform these
system calls until the revealed dependencies get satisfied. Crumb communicates
with its hooks via UNIX-domain sockets, and it communicates with the build system
using stdin/stdout.

Foe example, here's a wrapping of gcc via crumb:

   crumb gcc -c test/a.c -o test/a.o

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


People
------

For more questions, you can contact me: dan at aloni.org.
