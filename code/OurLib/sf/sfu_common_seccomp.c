#include "sf_internal.h"
#include "pk_internal.h"
#include "common_seccomp.h"
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>


// 32bit syscall numbers all have bit 30 set
#define X32_SYSCALL_BIT         0x40000000

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))


struct sock_filter seccomp_filter_base[] = {
#ifdef __x86_64__
    // check, if arch is x86_64
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#else
    // check, if arch is riscv
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_RISCV64, 1, 0),
#endif
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),

    // check, if it is not a compability syscall
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
#ifdef __x86_64__
    BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, X32_SYSCALL_BIT, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
#endif
};

struct sock_filter seccomp_filter_end[] = {
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
};

//------------------------------------------------------------------------------

static void _bpf_add_syscall(int cmd, struct sock_filter *filter, uint64_t sys_nr)
{
    struct sock_filter filter1[] = {
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sys_nr, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, cmd)
    };
    pk_memcpy(filter, filter1, sizeof(filter1));
}
//------------------------------------------------------------------------------

static void _bpf_add_filtered_syscall(int type, struct sock_filter *filter, uint64_t sys_nr)
{
    uint32_t cmd = type == SF_PTRACE_SECCOMP || type == SF_PTRACE_DELEGATE ? SECCOMP_RET_TRACE : SECCOMP_RET_USER_NOTIF;
    _bpf_add_syscall(cmd, filter, sys_nr);
}
//------------------------------------------------------------------------------

static void _bpf_add_denied_syscall(struct sock_filter *filter, uint64_t sys_nr)
{
    _bpf_add_syscall(SECCOMP_RET_ERRNO | EPERM, filter, sys_nr);
}
//------------------------------------------------------------------------------

#define SECCOMP_ALLOWED   0
#define SECCOMP_DENIED    1
#define SECCOMP_FILTERED  2


FORCE_INLINE int _all_active_filters(int active[])
{
    for (size_t i = 0; i < NUM_MONITOR_FILTERS; i++) {
        filter_t f = sf_table[i].filter;
        if (f == NULL) {
            //handle unknown syscalls
            //active[i] = SECCOMP_ALLOWED;
        }
        else if (f == SYSCALL_DENIED || f == SYSCALL_UNSPECIFIED) {
            active[i] = SECCOMP_DENIED;
        }
        else if (f != SYSCALL_ALLOWED) {
            active[i] = SECCOMP_FILTERED;
        }
    }

    for (int d = 0; d < NUM_DOMAINS; d++) {
        _pk_domain *domain = &pk_data.domains[d];
        if (!domain->used) {
            continue;
        }

        for (size_t i = 0; i < NUM_MONITOR_FILTERS; i++) {
            filter_t f = domain->sf_table[i].filter;
            if (f == NULL) {
                //handle unknown syscalls
                //active[i] = SECCOMP_ALLOWED;
            }
            else if (f == SYSCALL_DENIED || f == SYSCALL_UNSPECIFIED) {
                // do not deny syscalls that need to be filtered elsewhere
                if (active[i] != SECCOMP_FILTERED) {
                    active[i] = SECCOMP_DENIED;
                }
            }
            else if (f != SYSCALL_ALLOWED) {
                active[i] = SECCOMP_FILTERED;
            }
        }
    }

    int count = 0;
    for (int i = 0; i < NUM_MONITOR_FILTERS; i++) {
        if (active[i] != SECCOMP_ALLOWED) {
            ++count;
        }
    }
    return count;
}
//------------------------------------------------------------------------------

int _register_bpf_type(int type)
{
    int active_filters[NUM_MONITOR_FILTERS] = {SECCOMP_ALLOWED};
    int num_sysfilters = _all_active_filters(active_filters);
    DEBUG_SF("num sysfilters: %d", num_sysfilters);


    int filter_base_len = ARRAY_SIZE(seccomp_filter_base);
    int sysfilter_len = num_sysfilters * 2 + 1;
    int filter_len = filter_base_len + sysfilter_len;
    size_t filter_size = (size_t)filter_len * sizeof(struct sock_filter);

    struct sock_filter filter[filter_size];   // stack should easily be able to fit this
    pk_memcpy(filter, seccomp_filter_base, sizeof(seccomp_filter_base));

    struct sock_filter *pos = filter + filter_base_len;
    for (size_t i = 0; i < NUM_MONITOR_FILTERS; i++) {
        int filter = active_filters[i];
        if (filter == SECCOMP_FILTERED) {
            DEBUG_SF("SECCOMP_FILTERED %zu '%s'", i, sysno_to_str(i));
            _bpf_add_filtered_syscall(type, pos, i);
            pos += 2;
        }
        else if (filter == SECCOMP_DENIED) {
            DEBUG_SF("SECCOMP_DENIED   %zu '%s'", i, sysno_to_str(i));
            _bpf_add_denied_syscall(pos, i);
            pos += 2;
        }
    }
    pk_memcpy(pos, seccomp_filter_end, sizeof(seccomp_filter_end));

    struct sock_fprog prog = {
        .len = (unsigned short)filter_len,
        .filter = filter,
    };

    DEBUG_SF("registering seccomp bpf filter");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        ERROR_FAIL("could not start seccomp");
    }

    if (type == SF_PTRACE_SECCOMP || type == SF_PTRACE_DELEGATE) {
        return _seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog);
    }
    else if (type == SF_SECCOMP_USER) {
        return _seccomp(SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    }
    //DEBUG_SF("successfully registered seccomp bpf filter");

    return -1;
}
//------------------------------------------------------------------------------
