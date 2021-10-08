#pragma once

#include "sf_internal.h"
#include "pk_internal.h"
#include "pk_arch.h"
#include "sys/ptrace.h"
#include "elf.h"

struct sf_user_regs_struct {
	unsigned long pc;
	unsigned long ra;
	unsigned long sp;
	unsigned long gp;
	unsigned long tp;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long s0;
	unsigned long s1;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long s2;
	unsigned long s3;
	unsigned long s4;
	unsigned long s5;
	unsigned long s6;
	unsigned long s7;
	unsigned long s8;
	unsigned long s9;
	unsigned long s10;
	unsigned long s11;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
	unsigned long umpk;
};

typedef struct {
    bool used;                              // is tracee active
    bool is_exit;                           // is tracee at a exit stop
    pid_t pid;                              // pid of tracee
    _pk_tls *tls;                           // trusted tls of traced thread
    pkru_config_t old_pkru;                 // PKRU config before syscall
    int old_previous_slot;
    struct sf_user_regs_struct arch_regs;      // native thread registers
    trace_info_t info;
} tracee_t;

FORCE_INLINE void _deinit_tracee(tracee_t *tracee)
{
    tracee->used = false;
}
//------------------------------------------------------------------------------

FORCE_INLINE void _get_regs(tracee_t *tracee)
{
    trace_info_t *ti = &tracee->info;

    // get general purpose registers
    struct sf_user_regs_struct regs;
    struct iovec io = {
        .iov_base = &regs,
        .iov_len = sizeof(struct sf_user_regs_struct)
    };

    if (ptrace(PTRACE_GETREGSET, tracee->pid, NT_PRSTATUS, &io) != 0) {
        ERROR_FAIL("PTRACE_GETREGSET");
    }
    tracee->arch_regs = regs;

    // get all arg members, but the return value
    //Note: ptrace sf_user_regs_struct uses unsigned long long int, we're using long. hence the casts.
    ti->syscall_nr = (long)regs.a7;
    ti->args[0] = (long)regs.a0;
    ti->args[1] = (long)regs.a1;
    ti->args[2] = (long)regs.a2;
    ti->args[3] = (long)regs.a3;
    ti->args[4] = (long)regs.a4;
    ti->args[5] = (long)regs.a5;
    // note: this only works for same-address space ptracing
    // Use process_vmread instead
    tracee->tls = (_pk_tls *)(regs.tp + _pk_ttls_offset - offsetof(_pk_tls, backup_user_stack));
    ti->did = tracee->tls->current_did;
    pk_memcpy(ti->orig_args, ti->args, sizeof(ti->args));
}
//------------------------------------------------------------------------------

FORCE_INLINE void _set_regs(tracee_t *tracee)
{
    trace_info_t *ti = &tracee->info;

    // set all arg members, but the return value
    //Note: ptrace sf_user_regs_struct uses unsigned long long int, we're using long. hence the casts.
    tracee->arch_regs.a7 = IS_SYSCALL_ALLOWED(ti) ? (unsigned long long)ti->syscall_nr : -1ULL;
    tracee->arch_regs.a0 = (unsigned long long)ti->args[0];
    tracee->arch_regs.a1 = (unsigned long long)ti->args[1];
    tracee->arch_regs.a2 = (unsigned long long)ti->args[2];
    tracee->arch_regs.a3 = (unsigned long long)ti->args[3];
    tracee->arch_regs.a4 = (unsigned long long)ti->args[4];
    tracee->arch_regs.a5 = (unsigned long long)ti->args[5];
    struct iovec io = {
        .iov_base = &tracee->arch_regs,
        .iov_len = sizeof(struct sf_user_regs_struct)
    };
    if (ptrace(PTRACE_SETREGSET, tracee->pid, NT_PRSTATUS, &io) != 0) {
        ERROR_FAIL("PTRACE_SETREGS");
    }
}
//------------------------------------------------------------------------------

FORCE_INLINE void _get_return_reg(tracee_t *tracee)
{
    trace_info_t *ti = &tracee->info;
    struct sf_user_regs_struct regs;
    struct iovec io = {
        .iov_base = &regs,
        .iov_len = sizeof(struct sf_user_regs_struct)
    };

    if (ptrace(PTRACE_GETREGSET, tracee->pid, NT_PRSTATUS, &io) != 0) {
        ERROR_FAIL("PTRACE_GETREGSET");
    }
    tracee->arch_regs = regs;
    ti->return_value = (long) regs.a0;
}
//------------------------------------------------------------------------------

FORCE_INLINE void _set_return_reg(tracee_t *tracee)
{
    trace_info_t *ti = &tracee->info;

    // restore all arguments to the original state
    // (syscall calling convention!!)
    tracee->arch_regs.a7 = (unsigned long long)ti->syscall_nr;
    tracee->arch_regs.a0 = (unsigned long long)ti->return_value;
    tracee->arch_regs.a1 = (unsigned long long)ti->orig_args[1];
    tracee->arch_regs.a2 = (unsigned long long)ti->orig_args[2];
    tracee->arch_regs.a3 = (unsigned long long)ti->orig_args[3];
    tracee->arch_regs.a4 = (unsigned long long)ti->orig_args[4];
    tracee->arch_regs.a5 = (unsigned long long)ti->orig_args[5];

    struct iovec io = {
        .iov_base = &tracee->arch_regs,
        .iov_len = sizeof(struct sf_user_regs_struct)
    };
    if (ptrace(PTRACE_SETREGSET, tracee->pid, NT_PRSTATUS, &io) != 0) {
        ERROR_FAIL("PTRACE_SETREGS");
    }
}
//------------------------------------------------------------------------------

FORCE_INLINE void _load_syscall_args_key_sameprocess(tracee_t *tracee)
{
   ERROR_FAIL("not implemented");
}

FORCE_INLINE void _unload_syscall_args_key(tracee_t *tracee)
{
   ERROR_FAIL("not implemented");
}

FORCE_INLINE void _delegate_to_user(tracee_t *tracee)
{
   ERROR_FAIL("not implemented");
}
//------------------------------------------------------------------------------
