#include "sf_internal.h"
#include "common_seccomp.h"
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>


// 32bit syscall numbers all have bit 30 set
#define X32_SYSCALL_BIT         0x40000000

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

static int _register_bpf()
{
    struct sock_filter filter [] = {
/*#ifdef __x86_64__
        // check, if arch is x86_64
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 0, 2),
#else
        // check, if arch is riscv
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_RISCV64, 0, 2),
#endif

        // check, if it is not a compability syscall
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
#ifdef __x86_64__
        BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, X32_SYSCALL_BIT, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
#endif
*/
        // measure the overhead of seccomp + syscall
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)ARRAY_SIZE(filter),
        .filter = filter,
    };

    DEBUG_SF("registering seccomp bpf filter");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        ERROR_FAIL("could not start seccomp");
    }
    
    // DO NOT DO ANY FILTERED SYSCALLS (debug output, etc)
    // UNTIL WE SIGNALLED THE TRACER THREAD
    return _seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog);
}
//------------------------------------------------------------------------------

static void *_tracee_wrapper(void *arg)
{
    if (_register_bpf() < 0) {
        ERROR_FAIL("could not register bpf");
    }
    sf_tracee_function *start = (sf_tracee_function *)arg;
    exit(start->function(start->arg));
    return 0;
}
//------------------------------------------------------------------------------

int _sf_mechanism_seccomp(sf_tracee_function *start)
{
    start->wrapper = _tracee_wrapper;
    pid_t tracee = sf_start_tracee(start);
    assert(waitpid(tracee, NULL, 0) != -1);
    return 0;
}
//------------------------------------------------------------------------------

int _sf_mechanism_seccomp_ctor()
{
    if (_register_bpf() < 0) {
        ERROR_FAIL("could not register bpf");
    }
    return 0;
}
//------------------------------------------------------------------------------
