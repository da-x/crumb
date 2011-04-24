#!/usr/bin/env python

import sys, os, select, fcntl, re

defname = '_DEFAULT_'
crumbwrap_exe = 'crumbwrap'
crumbfile_name = 'Crumbfile'

class Error(Exception):
    pass

unescape_exp = re.compile("[<][<][<]([^>]+)[>][>][>]")
def unescape(line):
    m = unescape_exp.finditer(line)
    if not m:
        lst = [line]
    else:
        p = 0
        lst = []
        for i in m:
            st = i.start()
            en = i.end()
            ch = line[p:st]
            if ch:
                lst.append(ch)
            lst.append((line[st+3:en-3], ))
            p = en
        if p < len(line)-1:
            lst.append(line[p:])
    return lst

def remove_trailing_slash(path):
    while path.endswith('/'):
        path = path[:-1]
    return path

class CrumbFileResolvedDef(object):
    def __init__(self, toolspec, target_path, inputs_prefetch):
        self.toolspec = toolspec
        self.target_path = target_path
        self.inputs_prefetch = inputs_prefetch

class CrumbFile(object):
    def __init__(self, fulltarget_dir):
        self.fulltarget_dir = fulltarget_dir
        self.is_toplevel = False
        self.default_target = None
        self.rules_map = {}
        self.target_map = {}
        self.resolved_targets = {}
        self.inputs_to_prefetch = {}

    def parse_crumbfile(self, filename):
        f = open(filename, "r")
        for line in f.readlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                continue
            parts = unescape(line)
            if parts == [(":TOPLEVEL", )]:
                self.is_toplevel = True
                continue

            rule = None
            inputs_to_prefetch = []
            outputs = []

            for part in parts:
                if not isinstance(part, tuple):
                    continue

                part, = part
                if part.startswith('*'):
                    if rule:
                        raise Exception(parts)
                    rule = part[1:]
                    self.rules_map[part[1:]] = parts
                    continue
                if part.startswith('!'):
                    inputs_to_prefetch.extend(part[1:].split(' '))
                    continue
                if part.startswith('/'):
                    continue

                self.target_map[part] = parts
                outputs.append(part)
                if self.default_target is None:
                    self.default_target = part

            if inputs_to_prefetch:
                for outp in outputs:
                    self.inputs_to_prefetch[outp] = inputs_to_prefetch

        f.close()

    def resolve_target(self, target):
        if target == defname:
            target = self.default_target

        if target in self.resolved_targets:
            return self.resolved_targets[target]

        toolspec = self.target_map.get(target, None)
        prefetch = []
        toolspecstr = None
        if toolspec is None:
            # Crud - good for now but needs to be improved in term of performance
            for output_ext, otoolspec in self.rules_map.iteritems():
                if target.endswith(output_ext):
                    toolspec = otoolspec
                    break

        if toolspec:
            nparts = []
            for part in toolspec:
                if isinstance(part, tuple):
                    part, = part
                    if part.startswith('*'):
                        part = os.path.join(self.fulltarget_dir, target)
                    if part.startswith('!'):
                        inputs = [os.path.join(self.fulltarget_dir, p) for p in part[1:].split(' ')]
                        prefetch.extend(inputs)
                        part = ' '.join(inputs)
                    elif part == '\.':
                        part = os.path.join(self.fulltarget_dir, target[:-len(output_ext)])
                nparts.append(part)
            toolspecstr = ''.join(nparts)

        if toolspecstr:
            ret = CrumbFileResolvedDef(toolspecstr, os.path.join(self.fulltarget_dir, target), prefetch)
        else:
            ret = None

        self.resolved_targets[target] = ret
        return ret

crumb_files_parsed = {}
def get_crumb_of_dir(fulltarget_dir):
    if fulltarget_dir in crumb_files_parsed:
        cf = crumb_files_parsed.get(fulltarget_dir)
    else:
        fullname = os.path.join(fulltarget_dir, crumbfile_name)
        if not os.path.exists(fullname):
            raise Error("excepted a %s as %s, and file not found" % (crumbfile_name, fullname))
            return

        cf = CrumbFile(fulltarget_dir)
        cf.parse_crumbfile(fullname)
        crumb_files_parsed[fulltarget_dir] = cf

        if not cf.is_toplevel:
            # Then it's the not root project dir - try to find an upper CrumbFile
            upper_dir = os.path.normpath(os.path.join(fulltarget_dir, ".."))
            upper_cf = get_crumb_of_dir(upper_dir)

            # Inherit rules
            for key, value in upper_cf.rules_map.iteritems():
                if key not in cf.rules_map:
                    cf.rules_map[key] = value

    return cf

def get_crumb_def(fulltarget_dir, fulltarget_basename):
    cf = get_crumb_of_dir(fulltarget_dir)
    return cf.resolve_target(fulltarget_basename)

class CrumbLog(object):
    def __init__(self, prefix, parent=None, verbose=None):
        self.prefix = prefix
        self.parent = parent
        if verbose is not None:
            self.verbose = verbose
        else:
            self.verbose = parent.verbose

    def log(self, str):
        if self.parent:
            self.parent.log(self.prefix + str)
        else:
            print self.prefix + str

    def __call__(self, str):
        self.log(str)

class CrumbHalt(object):
    def __init__(self, target, msg):
        self.target = target
        self.msg = msg

class CrumbTarget(object):
    def __init__(self, tool, target_path, log=None):
        self.tool = tool
        self.path = target_path
        self.log = log
        self.status = ''
        self.created_paths = set()
        self.leaf_deps = set()
        self.deps_already_done = set()
        self.made = False

    def spawn(self, crumb):
        fromd, tod = os.pipe()
        fromc, toc = os.pipe()

        if self.log.verbose:
            self.log("executing: %s" % (self.tool, ))

        cmd = [crumb.crumb_wrap, "-f", str(fromc), str(tod), "/bin/sh", "-c", self.tool]
        pid = os.fork()
        if pid == 0:
            try:
                try:
                    os.close(toc)
                    os.close(fromd)
                    os.execv(crumb.crumb_wrap, cmd)
                except Exception, e:
                    from traceback import print_exc
                    print_exc(e)
            finally:
                os._exit(-1)
            return

        os.close(fromc)
        os.close(tod)
        self.pid = pid
        self.to_wrapper_fd = toc
        self.from_wrapper_fd = fromd
        fcntl.fcntl(fromd, fcntl.F_SETFL, fromd | os.O_NONBLOCK)
        crumb.rfd_map[fromd] = self
        crumb.rfd_list.append(fromd)

    def read(self, crumb):
        while True:
            try:
                c = os.read(self.from_wrapper_fd, 0x100)
                self.status += c
            except OSError:
                # Resource temporarily unavailable
                return
            if not c:
                self.collect_target(crumb)
                return
            if '\n' in self.status:
                break
        status = self.status.strip()
        self.status = ''
        parts = status.split(':')
        return parts

    def release(self, pid):
        os.write(self.to_wrapper_fd, 'RELEASE %s\n' % (pid, ))

    def collect_target(self, crumb):
        os.close(self.to_wrapper_fd)
        del self.to_wrapper_fd
        os.close(self.from_wrapper_fd)
        fromd = self.from_wrapper_fd
        del self.from_wrapper_fd
        del crumb.rfd_map[fromd]
        crumb.rfd_list.remove(fromd)
        (pid, status) = os.waitpid(self.pid, 0)
        del self.pid

        if os.WIFEXITED(status):
            self.log("tool exited (status=%d)" % (os.WEXITSTATUS(status), ))
        else:
            self.log("tool terminated (status=%d)" % (status, ))

        self.made = True
        crumb.target_ended(self)

class Crumb(object):
    def __init__(self):
        self._directory = os.getcwd()
        import sys
        self.exe_path = sys.argv[0]
        self.crumb_wrap = os.path.abspath(os.path.join(os.path.join(os.path.dirname(self.exe_path), crumbwrap_exe)))
        args = sys.argv[1:]
        if '-C' in args:
            i = args.index("-C")
            other_dir = args[i + 1]
            if other_dir.startswith("/"):
                self._directory = other_dir
            else:
                self._directory = os.path.normpath(os.path.join(self._directory, other_dir))
            del args[i:i+2]

        os.chdir(self._directory)
        self.cmdline_targets = args
        if not self.cmdline_targets:
            self.cmdline_targets = [defname]

        self.targets = {}
        self.deps_waiting = {}
        self.running_targets = []
        self.waiting_targets = []
        self.rfd_map = {}
        self.rfd_list = []
        self.log = CrumbLog("crumb: ", verbose=1)

    def run(self):
        for target in self.cmdline_targets:
            fulltarget_path = target
            fulltarget_dir = os.path.dirname(fulltarget_path)
            if os.path.isdir(fulltarget_path):
                fulltarget_path = os.path.join(fulltarget_dir, defname)
            fulltarget_basename = os.path.basename(fulltarget_path)
            resdef = get_crumb_def(fulltarget_dir, fulltarget_basename)
            if not resdef:
                raise Error("No target spec of %s in %s" % (fulltarget_basename, fulltarget_dir))
            if resdef.target_path not in self.targets:
                self.add_target(resdef)

        self.main_loop()

    def add_target(self, resdef):
        target = CrumbTarget(resdef.toolspec, resdef.target_path, log=CrumbLog("[%s]: " % (resdef.target_path, ), parent=self.log))
        self.targets[target.path] = target
        if len(self.running_targets) < 10: # TODO
            self.running_targets.append(target)
            target.spawn(self)
        else:
            self.waiting_targets.insert(0, target)
        if resdef.inputs_prefetch:
            for input_prefetch in resdef.inputs_prefetch:
                self.handle_prefetch(input_prefetch, target)
        return target

    def handle_prefetch(self, input_prefetch, from_target):
        reltarget = input_prefetch
        from_target.log("invoking prefetch on %s" % (input_prefetch, ))
        resdef = get_crumb_def(os.path.dirname(reltarget), os.path.basename(reltarget))
        if not resdef:
            if os.path.isfile(input_prefetch):
                from_target.log("leaf dep in prefetch: " + reltarget)
            else:
                raise Exception("don't know how to build %s" % (input_prefetch, ))
            return
        if reltarget not in self.targets:
            self.add_target(resdef)

    def target_ended(self, target):
        self.running_targets.remove(target)

        if target.path in self.deps_waiting:
            # Some targets are waiting for this one to end running
            halts = self.deps_waiting[target.path]
            for halt in halts:
                pid = halt.msg[0]
                halt.target.log("dep target %s completed, proceeding" % (target.path, ))
                halt.target.release(pid)
            del self.deps_waiting[target.path]

        if self.waiting_targets:
            # Some execution waited in line, spawn them
            new_target = self.waiting_targets.pop()
            self.running_targets.append(new_target)
            new_target.spawn(self)

    def handle_halt_queue(self, queue):
        for halt in queue:
            pid = halt.msg[0]
            mtype = halt.msg[1]
            if mtype == "VFS":
                func_effect, func_name, abspath = halt.msg[2:]
                abspathx = remove_trailing_slash(abspath)
                if not abspath.startswith(self._directory):
                    if func_effect == "MODIFY":
                        halt.target.created_paths.add(abspathx)
                    elif func_effect == "READ":
                        if not abspathx in halt.target.created_paths:
                            if os.path.isfile(abspathx):
                                # halt.target.log("TODO: external dep: " + abspathx)
                                pass
                    else:
                        raise Exception(parts)
                    halt.target.release(pid)
                    continue

                reltarget = abspath[len(self._directory)+1:]
                if not reltarget: # root dir stat
                    halt.target.release(pid)
                    continue

                resdef = get_crumb_def(os.path.dirname(reltarget), os.path.basename(reltarget))
                if not resdef:
                    # We don't know how to generate this target.
                    if func_effect == "READ":
                        # must be a leaf dep
                        if os.path.isfile(abspath):
                            # halt.target.log("TODO: internal leaf dep: " + reltarget)
                            if reltarget not in halt.target.leaf_deps:
                                halt.target.log("detected leaf dep: " + reltarget)
                            halt.target.leaf_deps.add(reltarget)
                            halt.target.release(pid)
                        else:
                            if not os.path.exists(abspath):
                                # halt.target.log("TODO: internal leaf dep (non-existing): " + reltarget)
                                pass
                            else:
                                halt.target.log("TODO: internal leaf dep (non-file): " + reltarget)
                            halt.target.release(pid)
                    elif func_effect == "MODIFY":
                        halt.target.log("detected internal tempfile: " + reltarget)
                        halt.target.release(pid)
                    else:
                        raise Exception(parts)
                else:
                    # We *do* know how to generate this target
                    if reltarget not in self.targets:
                        self.add_target(resdef)

                    target_path = resdef.target_path
                    dep_target = self.targets.get(target_path)
                    if func_effect == "MODIFY":
                        if dep_target is halt.target:
                            # It's us. Our output. Proceed.
                            halt.target.log("detected output: " + target_path)
                            halt.target.release(pid)
                        else:
                            # Nope, it's generating something else that doesn't belong to it
                            # but we know how to generate it ourselves, so something's amiss
                            halt.target.log("detected colliding side-effect: " + target_path)
                            raise Exception("can't handle it")
                    elif func_effect == "READ":
                        if dep_target.made:
                            # Already, done, proceed
                            if target_path not in halt.target.deps_already_done:
                                halt.target.log("dep target %s done already, proceeding" % (target_path, ))
                            halt.target.deps_already_done.add(target_path)
                            halt.target.release(pid)
                        else:
                            # Nope, we need to wait for it
                            if dep_target is halt.target:
                                # It's us. Our output. We try to probe it before generating it? No
                                # problem, make sure the old output isn't there, and proceed
                                if os.path.exists(abspath):
                                    os.unlink(abspath)
                                halt.target.release(pid)
                            else:
                                halt.target.log("waiting for dep target %s to be made" % (target_path, ))
                                self.deps_waiting.setdefault(target_path, []).append(halt)
                    else:
                        raise Exception(parts)
            else:
                raise Exception(parts)

    def main_loop(self):
        wfd = []
        efd = []
        queue = []
        while self.running_targets:
            rfd, wfd, efd = select.select(self.rfd_list, wfd, efd, 1.0)
            for fd in rfd:
                t = self.rfd_map[fd]
                msg = t.read(self)
                if msg:
                    queue.append(CrumbHalt(t, msg))
            self.handle_halt_queue(queue)
            queue = []

def main():
    try:
        crumb = Crumb()
        crumb.run()
        return 0
    except Error, e:
        print >>sys.stderr, "error: %s" % (e.args[0], )
        return -1

if __name__ == "__main__":
    sys.exit(main())
