
// from: https://stackoverflow.com/a/61001237

// eBPF API: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
//
// https://man7.org/linux/man-pages/man7/bpf-helpers.7.html

// NOTE: BPF only allows jumps (e.g. if-statements) of a certain length. So
// the program must be small or it will complain about "jump out of range from
// insn X to Y".

// NOTE: It looks like all helper functions must be inline. Otherwise it
// complains about "last insn is not an exit or jmp").  // TODO nope, even
// without noinline still get that error. // TODO it might be that we can't
// put bpf_get_current_task inside a function

#include <net/sock.h>
#include <linux/fs.h>

#define GRETEL_A_ERROR 0
#define GRETEL_A_SYSCALL_RECEIVE 1
#define GRETEL_A_SYSCALL_SEND 2
#define GRETEL_A_READ_INODE 3
#define GRETEL_A_WRITE_INODE 4
#define GRETEL_A_USER 5
#define GRETEL_A_BOOT 6
#define GRETEL_A_NEW_PID 7


struct gretel_struct {
    u64 a;
    u64 b;
    u64 c;
    u64 d;
};

typedef struct gretel_struct gretel_t;

static gretel_t mkgretel(u64 a, u64 b, u64 c, u64 d) {
    gretel_t res = {};
    res.a = a;
    res.b = b;
    res.c = c;
    res.d = d;
    return res;
}

static u64 gretel_random64() {
    return (((u64)bpf_get_prandom_u32() << 32) | (u64)bpf_get_prandom_u32());
}

static gretel_t gretel_random(u64 typ) {
    return mkgretel(typ, gretel_random64(), gretel_random64(), gretel_random64());
}

static gretel_t gretel_mkdefault(gretel_t *maybe_gretel) {
    return (maybe_gretel ? *maybe_gretel : mkgretel(GRETEL_A_ERROR,0,0,0));
}

#define PR_GRETEL_REQUEST_SET 9998
#define PR_GRETEL_RESPONSE_SET 9999

typedef struct {
    gretel_t parent_event_id;
    gretel_t event_id;
} lgretel_link_t;

typedef struct {
    gretel_t event_id;
    u32 lineno;
    // TODO maybe timestamp, etc.?
} lgretel_node_t;

#define LGRETEL_TYP_ERROR 0
#define LGRETEL_TYP_NODE 1
#define LGRETEL_TYP_LINK 2
typedef struct {
    u32 typ;
    union {
        lgretel_link_t link;
        lgretel_node_t node;
    } u;
} lgretel_logentry_t;
BPF_PERF_OUTPUT(events);

#define GRETEL_PASSTHROUGHMODE 1    // TODO remove?


static void do_gretel_log_node(void *ctx, gretel_t event_id, u32 lineno) {
    lgretel_logentry_t logentry = {};
    logentry.typ = LGRETEL_TYP_NODE;
    logentry.u.node.event_id = event_id;
    logentry.u.node.lineno = lineno;

     events.perf_submit(ctx, (char*)&logentry, sizeof(logentry));
}

#define gretel_log_node(ctx, event_id) do_gretel_log_node(ctx, event_id, __LINE__)

static void gretel_log_link(void *ctx, gretel_t parent_event_id, gretel_t event_id) {
    lgretel_logentry_t logentry = {};
    logentry.typ = LGRETEL_TYP_LINK;

    logentry.u.link.parent_event_id = parent_event_id;
    logentry.u.link.event_id = event_id;

     events.perf_submit(ctx, (char*)&logentry, sizeof(logentry));
}


BPF_HASH(gretel_pid_reqgrtls, u64, gretel_t);
BPF_HASH(gretel_pid_respgrtls, u64, gretel_t);
BPF_HASH(gretel_pid_curgrtls, u64, gretel_t);
BPF_HASH(gretel_pid_syscall_count, u64, u64);




struct inode_id {
    dev_t i_rdev;
    unsigned long i_ino;
};

static struct inode_id mkinodeid(struct inode *ino) {
    struct inode_id ii = {};
    ii.i_rdev = ino->i_rdev;
    ii.i_ino = ino->i_ino;
    return ii;
}

BPF_HASH(gretel_inode_lastwritegrtl, struct inode_id, gretel_t);

static void inode_gretel_set(struct inode *ino, gretel_t *new_gretel) {
    struct inode_id ii = mkinodeid(ino);
    gretel_inode_lastwritegrtl.update(&ii, new_gretel);
}

static gretel_t inode_gretel_get(struct inode *ino) {
    struct inode_id ii = mkinodeid(ino);
    gretel_t res = gretel_mkdefault(gretel_inode_lastwritegrtl.lookup(&ii));
    if (res.a == GRETEL_A_ERROR) {
        res = mkgretel(GRETEL_A_BOOT,0,0,0); // TODO try to initialize a
                                             // common gretel_boot variable so that
                                             // different boots get different
                                             // gretels.
    }
    return res;
}

static void inc_recvevent(u64 pid_tgid) {
    gretel_t sysreceive_event = {};
    u64 zero = 0;
    u64 *pnsys = gretel_pid_syscall_count.lookup_or_try_init(&pid_tgid, &zero);

    if (pnsys) { // should always be true unless we run out of memory.
        u64 nsys = __sync_fetch_and_add(pnsys, 1);
    }
}

static void inc_and_get_recvevent(u64 pid_tgid, u64 syscallid, gretel_t *res) {
    gretel_t sysreceive_event = {};
    u64 zero = 0;
    u64 *pnsys = gretel_pid_syscall_count.lookup_or_try_init(&pid_tgid, &zero);

    if (pnsys) { // should always be true unless we run out of memory.
        u64 nsys = __sync_fetch_and_add(pnsys, 1);

        sysreceive_event = mkgretel(GRETEL_A_SYSCALL_RECEIVE,pid_tgid,syscallid,nsys);
    } else {
        sysreceive_event = mkgretel(GRETEL_A_ERROR,47,0,0);
    }

    *res = sysreceive_event;
}

static void gretel_request_set(u64 pid_tgid, gretel_t *new_gretel) {
    gretel_pid_reqgrtls.update(&pid_tgid, new_gretel);
}

static void gretel_response_set(u64 pid_tgid, gretel_t *new_gretel) {
    gretel_pid_curgrtls.update(&pid_tgid, new_gretel);
}

static void gretel_current_set(u64 pid_tgid, gretel_t *new_gretel) {
    gretel_pid_respgrtls.update(&pid_tgid, new_gretel);
}

static gretel_t gretel_request_get(u64 pid_tgid) {
    gretel_t *gretelp = gretel_pid_reqgrtls.lookup(&pid_tgid);
    return gretel_mkdefault(gretelp);
}


static gretel_t gretel_response_get(u64 pid_tgid) {
    gretel_t *gretelp = gretel_pid_curgrtls.lookup(&pid_tgid);
    return gretel_mkdefault(gretelp);
}


static gretel_t gretel_current_get(u64 pid_tgid) {
    gretel_t *gretelp = gretel_pid_respgrtls.lookup(&pid_tgid);
    return gretel_mkdefault(gretelp);
}
// TODO clear out dead processes from datastructures

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();





    // NOTE: bpf_get_current_task must be called here and not from a function.
    // I think it is a macro that relies on args.
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {

        gretel_t request_event = gretel_request_get(pid_tgid);
        gretel_t sysreceive_event = {};

        inc_and_get_recvevent(pid_tgid, args->id, &sysreceive_event);

        if (request_event.a != GRETEL_A_ERROR) {
            gretel_log_link(args, request_event, sysreceive_event);
        }

        gretel_current_set(pid_tgid, &sysreceive_event);
    }
    return 0;
};

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    gretel_t current_event = gretel_current_get(pid_tgid);
    gretel_t response_event = gretel_response_get(pid_tgid);


    if (current_event.a != GRETEL_A_ERROR && response_event.a != GRETEL_A_ERROR) {
        gretel_log_link(args, current_event, response_event);
    }

    return 0;
};

static int gretel_is_enabled_for_current_task(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    gretel_t req_event = gretel_request_get(pid_tgid);

    return (req_event.a != GRETEL_A_ERROR);
}

static void gretel_current_push(struct pt_regs *ctx, gretel_t event) {

    if (GRETEL_PASSTHROUGHMODE && !gretel_is_enabled_for_current_task(ctx)) {
        // if user process did not provide a gretel number, then don't
        // register events that result from it at all.
        return;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();

    gretel_t current_event = gretel_current_get(pid_tgid);

    if (current_event.a != GRETEL_A_ERROR && event.a != GRETEL_A_ERROR) {
        gretel_log_link(ctx, current_event, event);
    }

    gretel_current_set(pid_tgid, &event); // TODO

    return;
}

static void gretel_do_ino_write(struct pt_regs *ctx, struct inode *ino) {

    if (GRETEL_PASSTHROUGHMODE && !gretel_is_enabled_for_current_task(ctx)) {
        gretel_t write_event = mkgretel(GRETEL_A_ERROR, 55, 0, 0);
        inode_gretel_set(ino, &write_event);
    } else {
        // TODO vs skip intermediate node here and just write cur to inode?
        gretel_t write_event = mkgretel(GRETEL_A_WRITE_INODE, ino->i_rdev, ino->i_ino, 0);
        gretel_current_push(ctx, write_event);
        inode_gretel_set(ino, &write_event);
    }
}

static void gretel_do_ino_read(struct pt_regs *ctx, struct inode *ino) {
    if (GRETEL_PASSTHROUGHMODE && !gretel_is_enabled_for_current_task(ctx)) {

    } else {
        gretel_t read_event = mkgretel(GRETEL_A_READ_INODE, ino->i_rdev, ino->i_ino, 0);
        gretel_current_push(ctx, read_event);

        gretel_t ino_gretel = inode_gretel_get(ino);
        gretel_log_link(ctx, ino_gretel, read_event);
    }
}

int kprobe__vfs_read(struct pt_regs *ctx, struct file *file, char *buf, size_t count, loff_t *pos) {
    struct inode *ino = file->f_inode;
    gretel_do_ino_read(ctx, ino);
    return 0;
}

int kprobe__sock_recvmsg(struct pt_regs *ctx, struct socket *sock, struct msghdr *msg, int flags) {
    struct inode *ino = SOCK_INODE(sock);
    gretel_do_ino_read(ctx, ino);
    return 0;
}


int kprobe__vfs_write(struct pt_regs *ctx, struct file *file, char *buf, size_t count, loff_t *pos) {
    struct inode *ino = file->f_inode;
    gretel_do_ino_write(ctx, ino);
    return 0;
}

int kprobe__sock_sendmsg(struct pt_regs *ctx, struct socket *sock, struct msghdr *msg, int flags) {
    struct inode *ino = SOCK_INODE(sock);
    gretel_do_ino_write(ctx, ino);
    return 0;
}


int syscall__prctl(struct pt_regs *ctx, int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    if (option == PR_GRETEL_REQUEST_SET) {
        gretel_t user_event = {};
        user_event.a = arg2;
        user_event.b = arg3;
        user_event.c = arg4;
        user_event.d = arg5;

        u64 pid_tgid = bpf_get_current_pid_tgid();
        gretel_request_set(pid_tgid, &user_event);
    } else if (option == PR_GRETEL_RESPONSE_SET) {
        gretel_t user_event = {};
        user_event.a = arg2;
        user_event.b = arg3;
        user_event.c = arg4;
        user_event.d = arg5;

        u64 pid_tgid = bpf_get_current_pid_tgid();
        gretel_response_set(pid_tgid, &user_event);
    }

    return 0;
}

int kprobe__sched_fork(struct pt_regs *ctx, unsigned long clone_flags, struct task_struct *p) {
    u64 parent_pid_tgid = bpf_get_current_pid_tgid();
    u64 child_pid_tgid = (((u64)p->tgid << 32) | (u64)p->pid);

    gretel_t parent_cur = gretel_current_get(parent_pid_tgid);
    if (GRETEL_PASSTHROUGHMODE && !gretel_is_enabled_for_current_task(ctx)) {

    } else {
        gretel_t pid_init_req = mkgretel(GRETEL_A_NEW_PID, child_pid_tgid, gretel_random64(), gretel_random64()); // TODO vs passthrough?

        //gretel_t pid_init_resp = gretel_request_get(parent_pid_tgid);
        gretel_t pid_init_resp = mkgretel(GRETEL_A_ERROR, 0, 0, 0);
        // TODO maybe delay response until wait()

        gretel_log_link(ctx, parent_cur, pid_init_req);
        gretel_request_set(child_pid_tgid, &pid_init_req);
        gretel_response_set(child_pid_tgid, &pid_init_resp);
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    //struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    //int exit_code = (task->exit_code >> 8);

    gretel_pid_reqgrtls.delete(&pid_tgid);
    gretel_pid_respgrtls.delete(&pid_tgid);
    gretel_pid_curgrtls.delete(&pid_tgid);

    return 0;
}

//RAW_TRACEPOINT_PROBE(sched_wakeup)
//{
//    struct task_struct *p = (struct task_struct *)ctx->args[0];
//    return trace_enqueue(p->tgid, p->pid);
//}

//int kprobe__ext4_file_read_iter(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *to) {
//    u32 event_type_id = 1;
//	  struct inode *ino = file_inode(iocb->ki_filp);
//    u64 event_id = ino->i_ino;
//    return gretel_current_push(ctx, event_type_id, event_id);
//}
