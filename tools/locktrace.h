struct lock_key {
    uint64_t uaddr;
    uint32_t pid;
    uint32_t tgid;
    int usr_stack_id;
    char comm[16]; // FIXME - TASK_COMM_LEN
};

struct lock_stats {
    uint64_t elapsed_blocked_us;
    uint64_t elapsed_sys_us;
    uint32_t max_blocked_us;
    uint32_t max_sys_us;
    uint32_t wait_count;
    uint32_t blocked_count;
    uint32_t wake_count;
    uint32_t errors;
};

struct sample_key {
    uint32_t pid;
    uint32_t tgid;
    int usr_stack_id;
    int kernel_stack_id;
    char comm[16]; // FIXME
};
