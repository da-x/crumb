#include <stdio.h>
#include <sched.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include "crumb.h"

struct crumb_ctx {
	char crumbwrap_path[0x200];
	char server_path[0x200];
	int serv_fd;
	pid_t TEMP_pid;
};

static pid_t spawn_with_fn(const char *program, char *const *args, void (*fn)(void *data), void *fn_data)
{
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		int ret;
		fn(fn_data);
		ret = execvp(program, args);
		exit(ret);
		return -1;
	}

	return pid;
}

static void fix_ld_preload(struct crumb_ctx *ctx)
{
	char buf[0x200];
	char add[0x200], *p;

	p = getenv("LD_PRELOAD");
	if (p != NULL) {
		snprintf(add, sizeof(add), " %s", p);
	} else {
		add[0] = '\0';
	}

	snprintf(buf, sizeof(buf), "%s%s", ctx->crumbwrap_path, add);
	setenv("LD_PRELOAD", buf, 1);
}

static void set_server_path(struct crumb_ctx *ctx)
{
	setenv("CRUMB_SERVER_PATH", ctx->server_path, 1);
}

static void fn(void *data)
{
	struct crumb_ctx *ctx = data;

	fix_ld_preload(ctx);
	set_server_path(ctx);
}

static int get_wrapper_path(struct crumb_ctx *ctx, char *arg)
{
	char *p, *d;
	struct stat st;
	int ret;

	if (arg[0] != '/') {
		char buf[0x200];
		char cwd[0x200];

		p = getcwd(cwd, sizeof(cwd));
		if (!p)
			return -1;

		snprintf(buf, sizeof(buf), "%s/%s", cwd, arg);
		p = strdup(buf);
	} else {
		p = strdup(arg);
		if (p == NULL)
			return -1;
	}

	d = dirname(p);
	snprintf(ctx->crumbwrap_path, sizeof(ctx->crumbwrap_path), "%s/%s", d, "crumbwrap.so");
	free(p);

	ret = stat(ctx->crumbwrap_path, &st);
	if (ret < 0)
		return -1;

	if (S_ISREG(st.st_mode))
		return 0;

	return -1;
}

static void crumb_main_loop(struct crumb_ctx *ctx)
{
	struct pollfd pfd[1];
	int ret, status;
	pid_t pid;

	while (1) {
		pfd[0].fd = ctx->serv_fd;
		pfd[0].revents = 0;
		pfd[0].events = POLLIN;

		ret = poll(&pfd[0], 1, 1000);
		if (ret > 0) {
			if (pfd[0].revents & POLLIN) {
				struct crumb_msg msg;
				struct sockaddr_un un;
				socklen_t addrlen = sizeof(un);

				ret = recvfrom(ctx->serv_fd, &msg, sizeof(msg), 0,
					       (struct sockaddr *)&un, &addrlen);
				printf("%d\n", ret);
			}
		}

		pid = waitpid(-1, &status, WNOHANG);
		if (pid == ctx->TEMP_pid) {
			break;
		}
	}
}

static int crumb_daemon_setup(struct crumb_ctx *ctx)
{
	struct sockaddr_un un;
	int ret;

	ctx->serv_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (ctx->serv_fd < 0)
		return ctx->serv_fd;

	ret = fcntl(ctx->serv_fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0)
		return ret;

	ret = fcntl(ctx->serv_fd, F_SETFL, fcntl(ctx->serv_fd, F_GETFL) & ~O_NONBLOCK);
	if (ret < 0)
		return ret;

	snprintf(ctx->server_path, sizeof(ctx->server_path), "/tmp/.crumbsock.%d", getpid());
	un.sun_family = AF_UNIX;
	snprintf(un.sun_path, sizeof(un.sun_path), "%s", ctx->server_path);

	ret = bind(ctx->serv_fd, (const struct sockaddr *)&un, sizeof(un));
	if (ret < 0)
		return ret;

	ret = listen(ctx->serv_fd, 100);
	if (ret < 0)
		return ret;

	return ret;
}

static int crumb_main(int argc, char *argv[], struct crumb_ctx *ctx)
{
	pid_t pid;
	int ret;

	if (argc < 1)
		return -1;

	ret = get_wrapper_path(ctx, argv[0]);
	if (ret)
		return ret;

	ret = crumb_daemon_setup(ctx);
	if (ret)
		return ret;

	pid = spawn_with_fn(argv[1], &argv[1], fn, ctx);
	if (pid > 0) {
		ctx->TEMP_pid = pid;

		crumb_main_loop(ctx);
	}

	unlink(ctx->server_path);
	return 0;
}

struct crumb_ctx g_ctx;

int main(int argc, char *argv[])
{
	return crumb_main(argc, argv, &g_ctx);
}
