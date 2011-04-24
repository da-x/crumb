/*
 * crumbwrap.so
 *
 * Based on source from:
 * auto-apt.so
 * on demand package installation tool
 * Copyright (c) 2000 Fumitoshi UKAI <ukai@debian.or.jp>
 * GPL
 *
 */
#define LARGEFILE_SOURCE
#define LARGEFILE64_SOURCE
#define __USE_LARGEFILE64 1
#define __USE_FILE_OFFSET64 1

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "crumb.h"

#define PKGCDB_AUTOCRUMB        1

#define CRUMB_HOOK_EXEC	0
#define CRUMB_HOOK_OPEN	1
#define CRUMB_HOOK_ACCESS	2
#define CRUMB_HOOK_STAT	3
#define NUM_CRUMB_HOOK  	4

static int debug, quiet, verbose;
static int crumb_fd = -1;
static struct sockaddr_un crumb_un_address;

#define DPRINT(x) do {} while (0)

#ifdef __alpha__
#define LIBCPATH "/lib/libc.so.6.1"
#else
#define LIBCPATH "/lib/libc.so.6"
#endif

typedef int (*funcptr) ();
typedef FILE *(*funcptr_fopen) ();
typedef char *(*getenv_func) (const char *);

static struct realfunctab {
	char *name;
	funcptr fptr;
} rftab[] = {
	{
	"execve", NULL},	/* execve(2) */
	    /* XXX: execl(3), execle(3) */
	    /* execlp(3)->execvp(3) */
	    /* execvp(3)->execv(3) */
	{
	"execv", NULL}, {
	"getenv", NULL}, {
	"chdir", NULL}, {
	"fchdir", NULL}, {
	"open", NULL}, {
	"open64", NULL}, {
	"fopen", NULL}, {
	"fopen64", NULL}, {
	"unlink", NULL},

#if 1
	{
	"__libc_open", NULL}, {
	"__libc_open64", NULL},
#endif
	{
	"access", NULL}, {
	"euidaccess", NULL}, {
	"create", NULL}, {
	"create64", NULL}, {
	"__xstat", NULL}, {
	"__xstat64", NULL}, {
	"__lxstat", NULL}, {
	"__lxstat64", NULL}, {
	NULL, NULL}
};

static char *orig_getenv(const char *name);

static void crumb_server_transaction(struct crumb_msg *msg)
{
	ssize_t ret;
	size_t nb = sizeof(*msg);

	ret = sendto(crumb_fd, msg, nb, 0, NULL, 0);

	if (ret < (ssize_t)nb) {
		fprintf(stderr, "crumb: failed message delivery, errno=%d\n", errno);
		exit(-1);
		return;
	}

	ret = recvfrom(crumb_fd, msg, sizeof(*msg), 0, NULL, 0);
	if (ret < (ssize_t)sizeof(*msg)) {
		fprintf(stderr, "crumb: failed getting a response to a message\n");
		exit(-1);
		return;
	}
}

static void check_file(const char *filename,
		       enum crumb_access_type access_type,
		       enum crumb_access_detail access_detail)
{
	struct crumb_msg msg;

	msg.type = CRUMB_MSG_TYPE_FILE_ACCESS;
	snprintf(msg.u.file_access.filename,
		 sizeof(msg.u.file_access.filename),
		 "%s", filename);
	msg.u.file_access.access_type = access_type;
	msg.u.file_access.access_detail = access_detail;
	crumb_server_transaction(&msg);
}

static void check_file_open(const char *filename, int flags)
{
	if (flags & O_WRONLY  ||  flags & O_RDWR) {
		if (flags & O_CREAT) {
			check_file(filename, CRUMB_ACCESS_TYPE_MODIFY, CRUMB_ACCESS_TYPE_CREATE_RDWR);
		} else {
			check_file(filename, CRUMB_ACCESS_TYPE_MODIFY, CRUMB_ACCESS_TYPE_OPEN_RDWR);
		}
	} else {
		check_file(filename, CRUMB_ACCESS_TYPE_READ, CRUMB_ACCESS_TYPE_OPEN_RDONLY);
	}
}

static void check_file_fopen(const char *filename, const char *mode)
{
	if (!strcmp("r", mode))
		check_file(filename, CRUMB_ACCESS_TYPE_READ, CRUMB_ACCESS_TYPE_OPEN_RDONLY);
	else if (!strcmp("r+", mode))
		check_file(filename, CRUMB_ACCESS_TYPE_READ, CRUMB_ACCESS_TYPE_OPEN_RDONLY);
	else if (!strcmp("w", mode))
		check_file(filename, CRUMB_ACCESS_TYPE_MODIFY, CRUMB_ACCESS_TYPE_CREATE_RDWR);
	else if (!strcmp("w+", mode))
		check_file(filename, CRUMB_ACCESS_TYPE_MODIFY, CRUMB_ACCESS_TYPE_OPEN_RDWR);
	else if (!strcmp("a", mode))
		check_file(filename, CRUMB_ACCESS_TYPE_MODIFY, CRUMB_ACCESS_TYPE_CREATE_RDWR);
	else if (!strcmp("a+", mode))
		check_file(filename, CRUMB_ACCESS_TYPE_MODIFY, CRUMB_ACCESS_TYPE_OPEN_RDWR);
	else if (!strcmp("rb", mode))
		check_file(filename, CRUMB_ACCESS_TYPE_READ, CRUMB_ACCESS_TYPE_OPEN_RDONLY);
	else if (!strcmp("r+b", mode))
		check_file(filename, CRUMB_ACCESS_TYPE_READ, CRUMB_ACCESS_TYPE_OPEN_RDONLY);
	else if (!strcmp("wb", mode))
		check_file(filename, CRUMB_ACCESS_TYPE_MODIFY, CRUMB_ACCESS_TYPE_CREATE_RDWR);
	else if (!strcmp("w+b", mode))
		check_file(filename, CRUMB_ACCESS_TYPE_MODIFY, CRUMB_ACCESS_TYPE_OPEN_RDWR);
	else if (!strcmp("ab", mode))
		check_file(filename, CRUMB_ACCESS_TYPE_MODIFY, CRUMB_ACCESS_TYPE_CREATE_RDWR);
	else if (!strcmp("a+b", mode))
		check_file(filename, CRUMB_ACCESS_TYPE_MODIFY, CRUMB_ACCESS_TYPE_OPEN_RDWR);
}

static char *crumbwarp_conf_var(char *name, char *def)
{
	char *p = orig_getenv(name);
	if (p == NULL)
		return def;
	if (*p == '\0')
		return def;
	return p;
}

static int crumbwarp_conf_switch(char *name)
{
	char *p = crumbwarp_conf_var(name, NULL);
	if (p == NULL)
		return 0;
	if (strcasecmp(p, "no") == 0 || strcasecmp(p, "off") == 0)
		return 0;
	return 1;
}

static void __attribute__ ((constructor)) crumbwrap_init(void)
{
	int ret;
	const char *crumb_path;

	crumb_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (crumb_fd < 0)
		exit(-1);

	ret = fcntl(crumb_fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		exit(-1);
		return;
	}

	crumb_path = orig_getenv(CRUMBWRAP_SERVER_PATH_ENV);
	if (!crumb_path) {
		exit(-1);
		return;
	}

	snprintf(crumb_un_address.sun_path, sizeof(crumb_un_address.sun_path), "%s", crumb_path);
	crumb_un_address.sun_family = AF_UNIX;

	ret = connect(crumb_fd, (const struct sockaddr *)&crumb_un_address, sizeof(crumb_un_address));
	if (ret < 0) {
		printf("crumbwrap: connect failed to %s, errno=%d\n", crumb_un_address.sun_path, errno);
		exit(-1);
		return;
	}

	if (crumbwarp_conf_switch("CRUMB_DEBUG")) {
		debug = 1;
	}
	if (crumbwarp_conf_switch("CRUMB_QUIET")) {
		quiet = 1;
	}
	if (crumbwarp_conf_switch("CRUMB_VERBOSE")) {
		verbose = 1;
	}
}

static funcptr load_library_symbol(char *name)
{
	void *handle;
	const char *error;
	struct realfunctab *ft;
	char *libcpath = NULL;

	for (ft = rftab; ft->name; ft++) {
		if (strcmp(name, ft->name) == 0) {
			if (ft->fptr != NULL) {
				return ft->fptr;
			}
			break;
		}
	}
	if (ft->name == NULL) {
		fprintf(stderr, "func:%s not found\n", name);
		return NULL;
	}

	libcpath = LIBCPATH;
	handle = dlopen(libcpath, RTLD_LAZY);
	if (!handle) {
		fprintf(stderr, "%s", dlerror());
		return NULL;
	}
	ft->fptr = dlsym(handle, ft->name);
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "dysym(%s)=%s\n", ft->name, error);
		ft->fptr = NULL;
	}
	dlclose(handle);
	return ft->fptr;
}

char *orig_getenv(const char *name)
{
	getenv_func __getenv;

	__getenv = (getenv_func)load_library_symbol("getenv");
	if (__getenv == NULL) {
		return NULL;
	}

	return __getenv(name);
}

int execl(const char *path, const char *arg, ...)
{
	size_t argv_max = 1024;
	const char **argv = alloca(argv_max * sizeof(const char *));
	unsigned int i;
	va_list args;
	argv[0] = arg;
	va_start(args, arg);
	i = 0;
	while (argv[i++] != NULL) {
		if (i == argv_max) {
			const char **nptr =
			    alloca((argv_max *= 2) * sizeof(const char *));
			argv = (const char **)memmove(nptr, argv, i);
			argv_max += i;
		}
		argv[i] = va_arg(args, const char *);
	}
	va_end(args);
	return execv(path, (char *const *)argv);
}

int execle(const char *path, const char *arg, ...)
{
	size_t argv_max = 1024;
	const char **argv = alloca(argv_max * sizeof(const char *));
	const char *const *envp;
	unsigned int i;
	va_list args;
	argv[0] = arg;
	va_start(args, arg);
	i = 0;
	while (argv[i++] != NULL) {
		if (i == argv_max) {
			const char **nptr =
			    alloca((argv_max *= 2) * sizeof(const char *));
			argv = (const char **)memmove(nptr, argv, i);
			argv_max += i;
		}
		argv[i] = va_arg(args, const char *);
	}
	envp = va_arg(args, const char *const *);
	va_end(args);
	return execve(path, (char *const *)argv, (char *const *)envp);
}

int execve(const char *filename, char *const argv[], char *const envp[])
{
	int e;
	funcptr __execve;

	DPRINT(("execve: filename=%s \n", filename));
	check_file(filename, CRUMB_ACCESS_TYPE_READ, CRUMB_ACCESS_TYPE_EXEC);
	__execve = load_library_symbol("execve");
	if (__execve == NULL) {
		errno = EINVAL;
		return -1;
	}
	DPRINT(("execve = %p\n", __execve));
	e = __execve(filename, argv, envp);
	DPRINT(("execve: filename=%s, e=%d\n", filename, e));
	return e;
}

int execv(const char *filename, char *const argv[])
{
	int e;
	funcptr __execv;

	DPRINT(("execv: filename=%s \n", filename));
	check_file(filename, CRUMB_ACCESS_TYPE_READ, CRUMB_ACCESS_TYPE_EXEC);
	__execv = load_library_symbol("execv");
	if (__execv == NULL) {
		errno = EINVAL;
		return -1;
	}
	DPRINT(("execv = %p :filename=%s %d\n",
		__execv, filename, apt));
	e = __execv(filename, argv);
	DPRINT(("execvp: filename=%s, e=%d\n", filename, e));
	return e;
}

#undef open
int open(const char *filename, int flags, ...)
{
	int e;
	funcptr __open;
	mode_t mode;
	va_list ap;

	DPRINT(("open: filename=%s \n", filename));

	check_file_open(filename, flags);

	__open = load_library_symbol("open");
	if (__open == NULL) {
		errno = ENOENT;
		return -1;
	}
	DPRINT(("open = %p\n", __open));
	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	e = __open(filename, flags, mode);
	DPRINT(("open: filename=%s e=%d\n", filename, e));
	return e;
}

#undef fopen64
FILE *fopen64(const char *filename, const char *mode)
{
	funcptr_fopen __open;
	FILE *f;

	DPRINT(("fopen: filename=%s \n", filename));
	check_file_fopen(filename, mode);
	__open = (funcptr_fopen)load_library_symbol("fopen64");
	if (__open == NULL) {
		errno = ENOENT;
		return NULL;
	}

	DPRINT(("open = %p\n", __open));
	f = __open(filename, mode);
	DPRINT(("open: filename=%s f=%p\n", filename, f));
	return f;
}

#undef fopen
FILE *fopen(const char *filename, const char *mode)
{
	funcptr_fopen __open;
	FILE *f;

	DPRINT(("fopen: filename=%s \n", filename));
	check_file_fopen(filename, mode);
	__open = (funcptr_fopen)load_library_symbol("fopen");
	if (__open == NULL) {
		errno = ENOENT;
		return NULL;
	}

	DPRINT(("open = %p\n", __open));
	f = __open(filename, mode);
	DPRINT(("open: filename=%s f=%p\n", filename, f));
	return f;
}

#if 1
#undef __libc_open
int __libc_open(const char *filename, int flags, ...)
{
	int e;
	funcptr __open;
	mode_t mode;
	va_list ap;

	DPRINT(("__libc_open: filename=%s \n", filename));
	check_file_open(filename, flags);
	__open = load_library_symbol("__libc_open");
	if (__open == NULL) {
		errno = ENOENT;
		return -1;
	}
	DPRINT(("__libc_open = %p\n", __open));
	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	e = __open(filename, flags, mode);
	DPRINT(("__libc_open: filename=%s e=%d\n", filename, e));
	return e;

}
#endif

#undef open64
int open64(const char *filename, int flags, ...)
{
	int e;
	funcptr __open;
	mode_t mode;
	va_list ap;

	DPRINT(("open64: filename=%s \n", filename));
	check_file_open(filename, flags);
	__open = load_library_symbol("open64");
	if (__open == NULL) {
		errno = ENOENT;
		return -1;
	}
	DPRINT(("open64 = %p\n", __open));
	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	e = __open(filename, flags, mode);
	DPRINT(("open64: filename=%s e=%d\n", filename, e));
	return e;
}

#undef creat
int creat(const char *filename, mode_t mode)
{
	int e;
	funcptr __creat;

	DPRINT(("creat: filename=%s \n", filename));
	check_file_open(filename, O_RDWR | O_CREAT);
	__creat = load_library_symbol("creat");
	if (__creat == NULL) {
		errno = ENOENT;
		return -1;
	}
	DPRINT(("creat = %p\n", __creat));
	e = __creat(filename, mode);
	DPRINT(("creat: filename=%s e=%d\n", filename, e));
	return e;
}

#undef creat64
int creat64(const char *filename, mode_t mode)
{
	int e;
	funcptr __creat;

	DPRINT(("creat64: filename=%s \n", filename));
	check_file_open(filename, O_RDWR | O_CREAT);
	__creat = load_library_symbol("creat64");
	if (__creat == NULL) {
		errno = ENOENT;
		return -1;
	}
	DPRINT(("creat64 = %p\n", __creat));
	e = __creat(filename, mode);
	DPRINT(("creat64: filename=%s e=%d\n", filename, e));
	return e;
}

#if 1
#undef __libc_open64
int __libc_open64(const char *filename, int flags, ...)
{
	int e;
	funcptr __open;
	mode_t mode;
	va_list ap;

	DPRINT(("__libc_open64: filename=%s \n", filename));
	check_file_open(filename, flags);
	__open = load_library_symbol("__libc_open64");
	if (__open == NULL) {
		errno = ENOENT;
		return -1;
	}
	DPRINT(("__libc_open64 = %p\n", __open));
	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	e = __open(filename, flags, mode);
	DPRINT(("__libc_open64: filename=%s e=%d\n", filename, e));
	return e;
}
#endif

int access(const char *filename, int type)
{
	int e;
	funcptr __access;

	DPRINT(("access: filename=%s \n", filename));
	check_file(filename, CRUMB_ACCESS_TYPE_READ, CRUMB_ACCESS_TYPE_ACCESS);
	__access = load_library_symbol("access");
	if (__access == NULL) {
		errno = ENOENT;
		return -1;
	}
	DPRINT(("access = %p\n", __access));
	e = __access(filename, type);
	DPRINT(("access: filename=%s e=%d\n", filename, e));
	return e;
}

int euidaccess(const char *filename, int type)
{
	int e;
	funcptr __euidaccess;

	DPRINT(("euidaccess: filename=%s \n", filename));
	check_file(filename, CRUMB_ACCESS_TYPE_READ, CRUMB_ACCESS_TYPE_ACCESS);
	__euidaccess = load_library_symbol("euidaccess");
	if (__euidaccess == NULL) {
		errno = ENOENT;
		return -1;
	}
	DPRINT(("euidaccess = %p\n", __euidaccess));
	e = __euidaccess(filename, type);
	DPRINT(("euidaccess: filename=%s e=%d\n", filename, e));
	return e;
}

#undef __xstat
int __xstat(int ver, const char *filename, struct stat *buf)
{
	int e;
	funcptr __stat;

	DPRINT(("stat: filename=%s \n", filename));
	check_file(filename, CRUMB_ACCESS_TYPE_READ, CRUMB_ACCESS_TYPE_STAT);
	__stat = load_library_symbol("__xstat");
	if (__stat == NULL) {
		errno = ENOENT;
		return -1;
	}
	DPRINT(("stat = %p\n", __stat));
	e = __stat(ver, filename, buf);
	DPRINT(("stat: filename=%s e=%d\n", filename, e));
	return e;
}

#undef __xstat64
struct stat64;			/* XXX */
int __xstat64(int ver, const char *filename, struct stat64 *buf)
{
	int e;
	funcptr __stat;

	DPRINT(("stat64: filename=%s \n", filename));
	check_file(filename, CRUMB_ACCESS_TYPE_READ, CRUMB_ACCESS_TYPE_STAT);
	__stat = load_library_symbol("__xstat64");
	if (__stat == NULL) {
		errno = ENOENT;
		return -1;
	}
	DPRINT(("stat64 = %p\n", __stat));
	e = __stat(ver, filename, buf);
	DPRINT(("stat64: filename=%s e=%d\n", filename, e));
	return e;
}

#undef __lxstat
int __lxstat(int ver, const char *filename, struct stat *buf)
{
	int e;
	funcptr __stat;

	DPRINT(("lstat: filename=%s \n", filename));
	check_file(filename, CRUMB_ACCESS_TYPE_READ, CRUMB_ACCESS_TYPE_STAT);
	__stat = load_library_symbol("__lxstat");
	if (__stat == NULL) {
		errno = ENOENT;
		return -1;
	}
	DPRINT(("lstat = %p\n", __stat));
	e = __stat(ver, filename, buf);
	DPRINT(("lstat: filename=%s e=%d\n", filename, e));
	return e;
}

#undef __lxstat64
int __lxstat64(int ver, const char *filename, struct stat64 *buf)
{
	int e;
	funcptr __stat;

	DPRINT(("lstat64: filename=%s \n", filename));
	check_file(filename, CRUMB_ACCESS_TYPE_READ, CRUMB_ACCESS_TYPE_STAT);
	__stat = load_library_symbol("__lxstat64");
	if (__stat == NULL) {
		errno = ENOENT;
		return -1;
	}
	DPRINT(("lstat64 = %p\n", __stat));
	e = __stat(ver, filename, buf);
	DPRINT(("lstat64: filename=%s e=%d\n", filename, e));
	return e;
}

#undef unlink
int unlink(const char *filename)
{
	int e;
	funcptr __unlink;

	DPRINT(("unlink filename=%s \n", filename));
	check_file(filename, CRUMB_ACCESS_TYPE_MODIFY, CRUMB_ACCESS_TYPE_UNLINK);
	__unlink = load_library_symbol("unlink");
	if (__unlink == NULL) {
		errno = ENOENT;
		return -1;
	}
	DPRINT(("unlink = %p\n", __unlink));
	e = __unlink(filename);
	DPRINT(("unlink filename=%s e=%d\n", filename, e));
	return e;
}

#undef chdir
int chdir(const char *filename)
{
	int e;
	funcptr __chdir;

	DPRINT(("chdir filename=%s \n", filename));
	check_file(filename, CRUMB_ACCESS_TYPE_READ, CRUMB_ACCESS_TYPE_CHDIR);
	__chdir = load_library_symbol("chdir");
	if (__chdir == NULL) {
		errno = ENOENT;
		return -1;
	}
	DPRINT(("chdir = %p\n", __chdir));
	e = __chdir(filename);
	DPRINT(("chdir filename=%s e=%d\n", filename, e));
	return e;
}

#undef fchdir
int fchdir(int fd)
{
	int e;
	funcptr __fchdir;

	DPRINT(("fchdir fd=%d \n", fd));
	printf("fchdir not handled\n");
	exit(-1);

	__fchdir = load_library_symbol("fchdir");
	if (__fchdir == NULL) {
		errno = ENOENT;
		return -1;
	}

	e = __fchdir(fd);
	DPRINT(("fchdir fd=%d\n", fd, e));
	return e;
}


#undef getenv
char *getenv(const char *name)
{
	return orig_getenv(name);
}

