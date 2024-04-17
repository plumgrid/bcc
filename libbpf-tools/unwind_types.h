// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright 2023 LG Electronics Inc.
#ifndef __UNWIND_TYPES_H
#define __UNWIND_TYPES_H

#define STRINGIFY(x)		#x
#define NAME(x)			STRINGIFY(x)

#define UW_STACK_MAX_SZ		4096
#define UW_SAMPLES_MAP		uw_samples
#define UW_STACKS_MAP		uw_stacks

#if defined(__TARGET_ARCH_arm64)
struct user_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#elif defined(__TARGET_ARCH_x86)
struct user_regs {
        __u64 r15;
        __u64 r14;
        __u64 r13;
        __u64 r12;
        __u64 bp;
        __u64 bx;
        __u64 r11;
        __u64 r10;
        __u64 r9;
        __u64 r8;
        __u64 ax;
        __u64 cx;
        __u64 dx;
        __u64 si;
        __u64 di;
        __u64 orig_ax;
        __u64 ip;
        __u64 cs;
        __u64 flags;
        __u64 sp;
        __u64 ss;
};
#else
#error This Architecture is not supported yet. Please open an issue
#endif

typedef struct user_regs regs_dump_t;

typedef struct stack_dump {
	__u32 size;
	char *data;
} stack_dump_t;

struct sample_data {
	regs_dump_t user_regs;
	stack_dump_t user_stack;
};
#endif /* __UNWIND_TYPES_H */
