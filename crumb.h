#ifndef __CRUMB_H__
#define __CRUMB_H__

enum crumb_msg_type {
	CRUMB_MSG_TYPE_NEW_PROCESS,
	CRUMB_MSG_TYPE_FILE_ACCESS,
	CRUMB_MSG_TYPE_CONTINUE,
};

struct crumb_msg_new_proc {
	int pid;
};

struct crumb_msg_file_access {
	char filename[0x200];
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

#endif
