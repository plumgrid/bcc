/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OFFWAKETIME_H
#define __OFFWAKETIME_H

#define TASK_COMM_LEN 16
struct pkey_t {
        __u32 pid;
        __u32 tgid;
        __u32 user_stack_id;
        __u32 kern_stack_id;
        char comm[TASK_COMM_LEN];
};

struct count_key_t {
        struct pkey_t waker;
        struct pkey_t target;
};
#endif /* __OFFWAKETIME_H */
