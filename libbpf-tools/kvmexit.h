/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __KVMEXIT_H
#define __KVMEXIT_H

struct exit_key {
	pid_t pid;
	pid_t tid;
	int exit_reason;
};

struct exit_stat {
	pid_t pid;
	pid_t tid;
	int exit_reason;
	int count;
};

#endif /* __KVMEXIT_H */
