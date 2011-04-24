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

#include "list.h"

#include "crumb.h"

#define MAX_CLIENTS 0x100

struct crumb_client {
	struct list_head node;
	int fd;

	int pfd_index;
	int blocked;
};

#define NON_CLIENTS_FDS   2

struct crumb_ctx {
	char crumbwrap_path[0x200];
	char server_path[0x200];

	struct pollfd pfd[MAX_CLIENTS + NON_CLIENTS_FDS];
	struct crumb_client *pfd_to_client[MAX_CLIENTS];
	struct crumb_client clients[MAX_CLIENTS];
	struct list_head free_clients_list;
	struct list_head dead_clients_list;
	int num_active_clients;
	int trace;

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
	snprintf(ctx->crumbwrap_path, sizeof(ctx->crumbwrap_path), "%s/%s", d, "crumbwrap_hooks.so");
	free(p);

	ret = stat(ctx->crumbwrap_path, &st);
	if (ret < 0)
		return -1;

	if (S_ISREG(st.st_mode))
		return 0;

	return -1;
}

static void crumb_handle_server_ready(struct crumb_ctx *ctx)
{
	struct pollfd *pfd = &ctx->pfd[0];
	struct sockaddr_un un;
	socklen_t addrlen = sizeof(un);
	int client_fd;

	pfd[0].revents &= ~POLLIN;

	if (list_empty(&ctx->free_clients_list)) {
		fprintf(stderr, "crumb: too many clients\n");
		exit(-1);
		return;
	}

	client_fd = accept(ctx->serv_fd, (struct sockaddr *)&un, &addrlen);
	if (client_fd >= 0) {
		struct crumb_client *client = list_first_entry(&ctx->free_clients_list, struct crumb_client, node);
		int pfd_index = ctx->num_active_clients;
		list_del_init(&client->node);

		client->fd = client_fd;
		client->pfd_index = pfd_index;
		ctx->pfd_to_client[pfd_index] = client;
		pfd[pfd_index + NON_CLIENTS_FDS].fd = client_fd;
		pfd[pfd_index + NON_CLIENTS_FDS].events = POLLIN;
		pfd[pfd_index + NON_CLIENTS_FDS].revents = 0;
		ctx->num_active_clients++;
	}

}

static void crumb_handle_unblock_client(struct crumb_ctx *ctx, struct crumb_client *client)
{
	int ret;

	if (client->blocked) {
		struct crumb_msg msg = {CRUMB_MSG_TYPE_CONTINUE, };
		ret = sendto(client->fd, &msg, sizeof(msg), 0, NULL, 0);
		client->blocked = 0;
	}
}

static void crumb_handle_client_ready(struct crumb_ctx *ctx)
{
	struct pollfd *pfd = &ctx->pfd[0];
	int i, ret;

	for (i = 0; i < ctx->num_active_clients; i++) {
		struct crumb_client *client = ctx->pfd_to_client[i];
		struct pollfd *cpfd = &pfd[i + NON_CLIENTS_FDS];

		if (cpfd->revents & POLLIN) {
			struct crumb_msg msg;
			cpfd->revents &= ~POLLIN;

			ret = recvfrom(client->fd, &msg, sizeof(msg), 0, NULL, 0);
			if (ret == 0) {
				list_add_tail(&client->node, &ctx->dead_clients_list);
				continue;
			}

			if (msg.type == CRUMB_MSG_TYPE_FILE_ACCESS) {
				const char *a = NULL, *d = NULL;

				switch (msg.u.file_access.access_type) {
				case CRUMB_ACCESS_TYPE_READ: a = "READ"; break;
				case CRUMB_ACCESS_TYPE_MODIFY: a = "MODIFY"; break;
				};

				switch (msg.u.file_access.access_detail) {
				case CRUMB_ACCESS_TYPE_OPEN_RDONLY: d = "OPEN_RDONLY"; break;
				case CRUMB_ACCESS_TYPE_OPEN_RDWR: d = "OPEN_RDWR"; break;
				case CRUMB_ACCESS_TYPE_CREATE_RDWR: d = "CREATE_RDWR"; break;
				case CRUMB_ACCESS_TYPE_STAT: d = "STAT"; break;
				case CRUMB_ACCESS_TYPE_ACCESS: d = "ACCESS"; break;
				case CRUMB_ACCESS_TYPE_UNLINK: d = "UNLINK"; break;
				case CRUMB_ACCESS_TYPE_DIROPEN: d = "DIROPEN"; break;
				case CRUMB_ACCESS_TYPE_EXEC: d = "EXEC"; break;
				};

				msg.type = CRUMB_MSG_TYPE_CONTINUE;

				printf("%ld:VFS:%s:%s:%s\n", client - &ctx->clients[0], a, d, msg.u.file_access.filename);
				client->blocked = 1;

				if (ctx->trace) {
					crumb_handle_unblock_client(ctx, client);
				}
			}
		}
	}

}

static void crumb_handle_stdin_ready(struct crumb_ctx *ctx)
{
	char command[0x200], *p;

	/* It better be a full line, otherwise we block */

	p = fgets(command, sizeof(command), stdin);
	if (p != NULL) {
		int client_id, ret;

		ret = sscanf(command, "RELEASE %d", &client_id);
		if (ret == 1) {
			if (client_id >= 0  &&  client_id < ctx->num_active_clients) {
				struct crumb_client *client = ctx->pfd_to_client[client_id];
				crumb_handle_unblock_client(ctx, client);
			}
		}
	}

}

static void crumb_prune_dead_clients(struct crumb_ctx *ctx)
{
	struct pollfd *pfd = &ctx->pfd[0];
	int i;

	while (!list_empty(&ctx->dead_clients_list)) {
		struct crumb_client *client = list_first_entry(&ctx->dead_clients_list, struct crumb_client, node);
		int pfd_index = client->pfd_index;
		struct pollfd *cpfd = &pfd[pfd_index + NON_CLIENTS_FDS];
		struct crumb_client **pfd_bp = &ctx->pfd_to_client[pfd_index];
		int pfds_after = (ctx->num_active_clients - pfd_index - 1);

		/* Close client */
		close(client->fd);
		list_del_init(&client->node);
		memset(client, 0, sizeof(*client));

		/* Trim it out of the PFD lists */
		for (i = pfd_index + 1; i < ctx->num_active_clients; i++) {
			ctx->pfd_to_client[i]->pfd_index--;
		}

		memmove(cpfd, &cpfd[1], sizeof(*cpfd)*pfds_after);
		memmove(pfd_bp, &pfd_bp[1], sizeof(*pfd_bp)*pfds_after);

		/* And free... */
		list_add(&client->node, &ctx->free_clients_list);
		ctx->num_active_clients--;
	}
}

static void crumb_main_loop(struct crumb_ctx *ctx)
{
	int ret, status, i;
	struct pollfd *pfd = &ctx->pfd[0];
	pid_t pid;

	pfd[0].fd = ctx->serv_fd;
	pfd[0].events = POLLIN;
	pfd[0].revents = 0;

	ret = fcntl(0, F_SETFL, fcntl(0, F_GETFL) & ~O_NONBLOCK);
	if (ret < 0)
		return;

	pfd[1].fd = 0;
	pfd[1].events = POLLIN;
	pfd[1].revents = 0;

	INIT_LIST_HEAD(&ctx->free_clients_list);
	INIT_LIST_HEAD(&ctx->dead_clients_list);

	for (i = 0; i < MAX_CLIENTS; i++) {
		struct crumb_client *client = &ctx->clients[i];
		list_add_tail(&client->node, &ctx->free_clients_list);
	}

	while (1) {
		ret = poll(&pfd[0], NON_CLIENTS_FDS + ctx->num_active_clients, 1000);
		if (ret > 0) {
			if (pfd[0].revents & POLLIN)
				crumb_handle_server_ready(ctx);

			if (pfd[1].revents & POLLIN)
				crumb_handle_stdin_ready(ctx);

			crumb_handle_client_ready(ctx);
		}

		/* Prune dead clients */
		crumb_prune_dead_clients(ctx);

		/* Check if our top-level process died or not */
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

	if (argc >= 2) {
		if (!strcmp(argv[1], "-s")) {
			ctx->trace = 1;
			argv++;
			argc--;
		}
	}

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
