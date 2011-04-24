#ifndef __CRUMB_H__
#define __CRUMB_H__

enum crumb_msg_type {
	CRUMB_MSG_TYPE_NEW_PROCESS,
	CRUMB_MSG_TYPE_FILE_ACCESS,
	CRUMB_MSG_TYPE_CONTINUE,
};

enum crumb_access_type {
	CRUMB_ACCESS_TYPE_READ,
	CRUMB_ACCESS_TYPE_MODIFY,
};

enum crumb_access_detail {
	CRUMB_ACCESS_TYPE_OPEN_RDONLY,
	CRUMB_ACCESS_TYPE_OPEN_RDWR,
	CRUMB_ACCESS_TYPE_CREATE_RDWR,
	CRUMB_ACCESS_TYPE_STAT,
	CRUMB_ACCESS_TYPE_ACCESS,
	CRUMB_ACCESS_TYPE_UNLINK,
	CRUMB_ACCESS_TYPE_DIROPEN,
	CRUMB_ACCESS_TYPE_EXEC,
};

struct crumb_msg_new_proc {
	int pid;
};

struct crumb_msg_file_access {
	char filename[0x200];
	enum crumb_access_type access_type;
	enum crumb_access_detail access_detail;
};

struct crumb_msg_continue {
};

struct crumb_msg {
	enum crumb_msg_type type;
	union {
		struct crumb_msg_new_proc new_proc;
		struct crumb_msg_file_access file_access;
	} u;
};


#define CRUMBWRAP_SERVER_PATH_ENV "CRUMBWRAP_SERVER_PATH"

#endif
