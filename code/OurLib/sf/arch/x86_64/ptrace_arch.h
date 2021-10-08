#pragma once

#include "sf_internal.h"
#include "pk_internal.h"
#include "pk_arch.h"
#include "sysfilter.h"
#include "elf.h"
#include <sys/ptrace.h>
#include <cpuid.h>

extern size_t arch_xstate_size;

#define XSTATE_XCR0_OFFSET      464
#define XSTATE_XCR0_INDEX       (XSTATE_XCR0_OFFSET / sizeof(uint32_t))
#define XSTATE_HAS_PKRU_MASK    (1ULL << 9)
#define XSTATE_PKRU_OFFSET      2688
#define XSTATE_PKRU_INDEX       (XSTATE_PKRU_OFFSET / sizeof(uint32_t))
#define XSTATE_MAX_SIZE         3000

struct sf_user_regs_struct
{
  __extension__ unsigned long long int r15;
  __extension__ unsigned long long int r14;
  __extension__ unsigned long long int r13;
  __extension__ unsigned long long int r12;
  __extension__ unsigned long long int rbp;
  __extension__ unsigned long long int rbx;
  __extension__ unsigned long long int r11;
  __extension__ unsigned long long int r10;
  __extension__ unsigned long long int r9;
  __extension__ unsigned long long int r8;
  __extension__ unsigned long long int rax;
  __extension__ unsigned long long int rcx;
  __extension__ unsigned long long int rdx;
  __extension__ unsigned long long int rsi;
  __extension__ unsigned long long int rdi;
  __extension__ unsigned long long int orig_rax;
  __extension__ unsigned long long int rip;
  __extension__ unsigned long long int cs;
  __extension__ unsigned long long int eflags;
  __extension__ unsigned long long int rsp;
  __extension__ unsigned long long int ss;
  __extension__ unsigned long long int fs_base;
  __extension__ unsigned long long int gs_base;
  __extension__ unsigned long long int ds;
  __extension__ unsigned long long int es;
  __extension__ unsigned long long int fs;
  __extension__ unsigned long long int gs;
};

typedef struct {
    bool used;                              // is tracee active
    bool is_exit;                           // is tracee at a exit stop
    pid_t pid;                              // pid of tracee
    _pk_tls *tls;                           // trusted tls of traced thread
    pkru_config_t old_pkru;                 // PKRU config before syscall
    struct sf_user_regs_struct arch_regs;      // native thread registers
    uint32_t arch_xstate[XSTATE_MAX_SIZE / sizeof(uint32_t)];  // native eXtended register state
    trace_info_t info;
} tracee_t;

FORCE_INLINE void _deinit_tracee(tracee_t *tracee)
{
    tracee->used = false;
    free(tracee->arch_xstate);
}
//------------------------------------------------------------------------------

FORCE_INLINE void _get_regs_generic(tracee_t *tracee)
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
    ti->syscall_nr = (long)regs.orig_rax;
    ti->args[0] = (long)regs.rdi;
    ti->args[1] = (long)regs.rsi;
    ti->args[2] = (long)regs.rdx;
    ti->args[3] = (long)regs.r10;
    ti->args[4] = (long)regs.r8;
    ti->args[5] = (long)regs.r9;

    tracee->tls = NULL;
    ti->did = DID_INVALID;
    pk_memcpy(ti->orig_args, ti->args, sizeof(ti->args));
}
//------------------------------------------------------------------------------

FORCE_INLINE void _get_regs_sameprocess(tracee_t *tracee)
{
    _get_regs_generic(tracee);
    trace_info_t *ti = &tracee->info;

    // Retrieve same-process TLS pointer
    tracee->tls = (_pk_tls *)(tracee->arch_regs.fs_base + _pk_ttls_offset - offsetof(_pk_tls, backup_user_stack));
    ti->did = tracee->tls->current_did; // access same-process TLS
}
//------------------------------------------------------------------------------

FORCE_INLINE void _set_regs(tracee_t *tracee)
{
    trace_info_t *ti = &tracee->info;

    // set all arg members, but the return value
    //Note: ptrace sf_user_regs_struct uses unsigned long long int, we're using long. hence the casts.
    tracee->arch_regs.orig_rax = IS_SYSCALL_ALLOWED(ti) ? (unsigned long long)ti->syscall_nr : -1ULL;
    tracee->arch_regs.rdi = (unsigned long long)ti->args[0];
    tracee->arch_regs.rsi = (unsigned long long)ti->args[1];
    tracee->arch_regs.rdx = (unsigned long long)ti->args[2];
    tracee->arch_regs.r10 = (unsigned long long)ti->args[3];
    tracee->arch_regs.r8  = (unsigned long long)ti->args[4];
    tracee->arch_regs.r9  = (unsigned long long)ti->args[5];
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
    ti->return_value = ptrace(PTRACE_PEEKUSER, tracee->pid, offsetof(struct sf_user_regs_struct, rax), 0);
    if (errno != 0) {
        ERROR_FAIL("PTRACE_PEEKUSER");
    }
}
//------------------------------------------------------------------------------

FORCE_INLINE void _set_return_reg(tracee_t *tracee)
{
    trace_info_t *ti = &tracee->info;

    // restore all arguments to the original state
    // (syscall calling convention!!)
    tracee->arch_regs.rax = (unsigned long long)ti->return_value;
    tracee->arch_regs.rdi = (unsigned long long)ti->orig_args[0];
    tracee->arch_regs.rsi = (unsigned long long)ti->orig_args[1];
    tracee->arch_regs.rdx = (unsigned long long)ti->orig_args[2];
    tracee->arch_regs.r10 = (unsigned long long)ti->orig_args[3];
    tracee->arch_regs.r8  = (unsigned long long)ti->orig_args[4];
    tracee->arch_regs.r9  = (unsigned long long)ti->orig_args[5];
    struct iovec io = {
        .iov_base = &tracee->arch_regs,
        .iov_len = sizeof(struct sf_user_regs_struct)
    };
    if (ptrace(PTRACE_SETREGSET, tracee->pid, NT_PRSTATUS, &io) != 0) {
        ERROR_FAIL("PTRACE_SETREGS");
    }
}
//------------------------------------------------------------------------------

FORCE_INLINE size_t _get_arch_xstate_size()
{
    if (arch_xstate_size != 0) {
        return arch_xstate_size;
    }

    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx) || !(ecx & bit_XSAVE)) {
        ERROR_FAIL("XSTATE: not suppported");
    }

    if (!__get_cpuid_count(0x0d, 0, &eax, &ebx, &ecx, &edx)) {
        ERROR_FAIL("XSTATE: could not read max size");
        exit(1);
    }
    DEBUG_SF("XSTATE size is %u", ecx);
    arch_xstate_size = ecx;
    assert(arch_xstate_size <= XSTATE_MAX_SIZE);
    return arch_xstate_size;
}
//------------------------------------------------------------------------------

FORCE_INLINE pkru_config_t _get_pkru(tracee_t *tracee)
{
    // get eXtended register state (PKRU)
    uint32_t *xstate = tracee->arch_xstate;
    struct iovec io = {
        .iov_base = xstate,
        .iov_len = _get_arch_xstate_size()
    };

    if (ptrace(PTRACE_GETREGSET, tracee->pid, NT_X86_XSTATE, &io) != 0) {
        ERROR_FAIL("PTRACE_GETREGSET xstate");
    }

    uint32_t xcr0 = xstate[XSTATE_XCR0_INDEX];
    if (!(xcr0 & XSTATE_HAS_PKRU_MASK)) {
        ERROR_FAIL("xstate does not have pkru");
    }

    return (pkru_config_t)xstate[XSTATE_PKRU_INDEX];
}

FORCE_INLINE void _set_pkru(tracee_t *tracee, pkru_config_t pkru)
{
    // set eXtended register state (PKRU)
    struct iovec io = {
        .iov_base = tracee->arch_xstate,
        .iov_len = _get_arch_xstate_size()
    };
    tracee->arch_xstate[XSTATE_PKRU_INDEX] = (uint32_t)pkru;

    if (ptrace(PTRACE_SETREGSET, tracee->pid, NT_X86_XSTATE, &io) != 0) {
        ERROR_FAIL("PTRACE_SETREGSET xstate");
    }
}

#if !defined(FAKE_MPK_REGISTER)
FORCE_INLINE void _load_syscall_args_key_sameprocess(tracee_t *tracee)
{
    pkru_config_t config = _get_pkru(tracee);
    tracee->old_pkru = config;
    //assert(tracee->tls->asm_pkru == config); // access same-process TLS

    pk_key_t *syscall_args_key = &tracee->tls->syscall_args_key; // access same-process TLS
    const pkru_config_t mask = (pkru_config_t)(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE) << (syscall_args_key->pkey*2);
    config &= ~mask;  // syscall args key does not have permission restrictions
    _set_pkru(tracee, config);
}

FORCE_INLINE void _unload_syscall_args_key(tracee_t *tracee)
{
    _set_pkru(tracee, tracee->old_pkru);
}
#else
#define _load_syscall_args_key_sameprocess(tracee) do {} while(0)
#define _unload_syscall_args_key(tracee) do {} while(0)
#endif
//------------------------------------------------------------------------------

FORCE_INLINE void _delegate_to_user(tracee_t *tracee)
{
    DEBUG_SF("delegating %s", sysno_to_str(tracee->info.syscall_nr));
    DEBUG_SF("original rip: %llx, original stack: %llx", tracee->arch_regs.rip, tracee->arch_regs.rsp);
    tracee->arch_regs.rcx = tracee->arch_regs.rip;
    tracee->arch_regs.rip = ((uint64_t)_pk_syscall_handler);
    tracee->arch_regs.rax = tracee->info.syscall_nr;
}
//------------------------------------------------------------------------------

FORCE_INLINE int _filter_syscalls_pku(tracee_t *tracee)
{
    pkru_config_t pkru = _get_pkru(tracee);
    return pkru & SYSFILTER_DELEGATE_MASK;
}
