#pragma once
#include "sf_internal.h"
#include "pk_internal.h"
#include "ptrace_arch.h"
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <elf.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>


typedef struct {
    pid_t pid;
    int signal;
    int event;
} event_t;

extern tracee_t tracees[NUM_THREADS];
extern int tracees_count;

//------------------------------------------------------------------------------

FORCE_INLINE const char * _ptrace_event_to_str(int event)
{
    assert(event <= PTRACE_EVENT_STOP);

    static const char * events[PTRACE_EVENT_STOP+1] = {
        [PTRACE_EVENT_FORK]       = "PTRACE_EVENT_FORK",
        [PTRACE_EVENT_VFORK]      = "PTRACE_EVENT_VFORK",
        [PTRACE_EVENT_CLONE]      = "PTRACE_EVENT_CLONE",
        [PTRACE_EVENT_EXEC]       = "PTRACE_EVENT_EXEC",
        [PTRACE_EVENT_VFORK_DONE] = "PTRACE_EVENT_VFORK_DONE",
        [PTRACE_EVENT_EXIT]       = "PTRACE_EVENT_EXIT",
        [PTRACE_EVENT_SECCOMP]    = "PTRACE_EVENT_SECCOMP",
        [PTRACE_EVENT_STOP]       = "PTRACE_EVENT_STOP",
    };

    return events[event];
}
//------------------------------------------------------------------------------

FORCE_INLINE void _init_tracee(tracee_t *tracee, pid_t pid)
{
    tracee->used = true;
    tracee->is_exit = false;
    tracee->pid = pid;
}
//------------------------------------------------------------------------------

FORCE_INLINE tracee_t *_get_tracee_by_pid(pid_t pid)
{
    for (int i = 0; i < NUM_THREADS; i++) {
        if (tracees[i].used && tracees[i].pid == pid) {
            return &tracees[i];
        }
    }
    return NULL;
}
//------------------------------------------------------------------------------

FORCE_INLINE int _add_tracee(pid_t pid)
{
    for (int i = 0; i < NUM_THREADS; i++) {
        if (!tracees[i].used) {
            _init_tracee(&tracees[i], pid);
            ++tracees_count;
            return 0;
        }
    }
    return -1;
}
//------------------------------------------------------------------------------

FORCE_INLINE int _remove_tracee(pid_t pid)
{
    for (int i = 0; i < NUM_THREADS; i++) {
        if (tracees[i].used && tracees[i].pid == pid) {
            _deinit_tracee(&tracees[i]);
            --tracees_count;
            return 0;
        }
    }
    return -1;
}
//------------------------------------------------------------------------------

/**
 * @brief Executes syscall entering hook.
 *
 * Allows / denies or filters syscall entering according to the sf_table.
 *
 * @param ti
 *          information about the trace
 *
 */
FORCE_INLINE void _handle_enter_syscall_sameprocess(tracee_t *tracee)
{
    trace_info_t *ti = &tracee->info;
    ti->flags = 0;

    _get_regs_sameprocess(tracee);
    if (!_filter_syscalls_pku(tracee)/*tracee->tls->filter_syscalls*/) {
        DEBUG_SF("allowing monitor %s(%lu, %lu, %lu, %lu, %lu, %lu)", sysno_to_str(ti->syscall_nr), ti->args[0], ti->args[1], ti->args[2], ti->args[3], ti->args[4], ti->args[5]);
        SET_SYSCALL_ALLOWED(ti);
        return;
    }
    assert(ti->syscall_nr >= 0 && ti->syscall_nr < NUM_DOMAIN_FILTERS);

    sysent_t *sysent = &sf_table[ti->syscall_nr];
    if (sysent->filter == SYSCALL_DENIED) {
        ERROR("denying %s(%lu, %lu, %lu, %lu, %lu, %lu)", sysno_to_str(ti->syscall_nr), ti->args[0], ti->args[1], ti->args[2], ti->args[3], ti->args[4], ti->args[5]);
        SET_SYSCALL_DENIED(ti);
        ti->return_value = -EPERM;
        _set_regs(tracee);
    }
    else if (sysent->filter == SYSCALL_ALLOWED) {
        DEBUG_SF("allowing %s(%lu, %lu, %lu, %lu, %lu, %lu)", sysno_to_str(ti->syscall_nr), ti->args[0], ti->args[1], ti->args[2], ti->args[3], ti->args[4], ti->args[5]);
        SET_SYSCALL_ALLOWED(ti);
    }
    else {
        DEBUG_SF("filtering %s(%lu, %lu, %lu, %lu, %lu, %lu)", sysno_to_str(ti->syscall_nr), ti->args[0], ti->args[1], ti->args[2], ti->args[3], ti->args[4], ti->args[5]);
        SET_SYSCALL_FILTERED(ti);

        // get args memory
        // access same-process TLS
        _pk_thread_domain* thread_domain = _pk_get_thread_domain_data_tls_nodidcheck(ti->did, tracee->tls);
        ti->mem = thread_domain->syscall.filter_mem;
        ti->mem_offset = 0;

        // error checks
        if (sysent->filter == SYSCALL_UNSPECIFIED) {
            ERROR_FAIL("TODO: handle syscall %3ld '%s'", ti->syscall_nr, sysent_to_syscall_str(sysent));
        }
        assert_ifdebug((long)sysent->filter > 0);

        if (sf_arg_copy_syscall_enter(ti, sysent->arg_copy) == -1) {
            SET_SYSCALL_DENIED(ti);
            ti->return_value = -errno;
        }
        else {
            sysent->filter(ti);
        }

        //_pk_release_lock();

        // is the same as IS_SYSCALL_FILTERED(ti) && IS_SYSCALL_ALLOWED(ti)
        if (IS_SYSCALL_ALLOWED(ti)) {
            _load_syscall_args_key_sameprocess(tracee);
        }
        _set_regs(tracee);
    }
}
//------------------------------------------------------------------------------

/**
 * @brief Executes syscall exiting hook.
 *
 * Allows / denies or filters syscall exiting according to the sf_table.
 *
 * @param ti
 *          information about the trace
 *
 */
FORCE_INLINE void _handle_exit_syscall(tracee_t *tracee)
{
    trace_info_t *ti = &tracee->info;
    if (IS_SYSCALL_FILTERED(ti)) {
        assert(ti->syscall_nr >= 0 && ti->syscall_nr < NUM_DOMAIN_FILTERS);
        sysent_t *sysent = &sf_table[ti->syscall_nr];

        if (IS_SYSCALL_ALLOWED(ti)) {
            _get_return_reg(tracee);
            assert(sysent->filter != SYSCALL_ALLOWED && sysent->filter != SYSCALL_DENIED);

            _unload_syscall_args_key(tracee);

            SET_SYSCALL_EXIT(ti);
            sysent->filter(ti);
        }

        // also restore args for filters that don't execute the syscall
        if (sf_arg_copy_syscall_exit(ti, sysent->arg_copy) == -1) {
            ti->return_value = -errno;
        }
        //_pk_release_lock();
    }

    // IS_SYSCALL_FILTERED: return value set in ENTER or EXIT filter
    // IS_SYSCALL_DENIED: can also be set be ENTER filter
    // IS_SYSCALL_ALLOWED: return value does change -> do not need to set the register
    if (!IS_SYSCALL_ALLOWED(ti)) {
        _set_return_reg(tracee);
    }
}
//------------------------------------------------------------------------------

/**
 * @brief Waits for the given PID to receive a signal.
 *
 * This function calls waitpid on the given PID. If the PID > 0, it will wait
 * for a specific process, if it PID == -1 it waits for any child PID.
 * The function detects and handles PIDs that exited, signaled and died, or got
 * stopped by a signal.
 *
 * @param pid
 *          a specific PID (> 0) or -1 to wait for any child
 * @param out_event
 *          info about the current event (e.g. pid, signal nr, ...)
 * @return
 *          0
 *              if the pid in out_event->pid is still alive
 *          1
 *              if the pid in out_event->pid died
 *
 */
FORCE_INLINE int _next_event(pid_t pid, event_t *out_event)
{
    assert(out_event);

    int status;
    pid_t tracee = waitpid(pid, &status, __WALL);

    if (tracee == -1 || status == -1) {
        ERROR_FAIL("cannot wait on any tracee");
    }

    if (WIFEXITED(status)) {
        DEBUG_MPK("WIFEXITED from pid %u", tracee);
        --tracees_count;
    }
    else if (WIFSIGNALED(status)) {
        DEBUG_MPK("WIFSIGNALED from pid %u, signal: %d '%s'", tracee, WTERMSIG(status), strsignal(WTERMSIG(status)));
        --tracees_count;
    }
    else if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        int event = status >> 16;

        out_event->pid = tracee;
        out_event->signal = sig;
        out_event->event = event;

        // PTRACE_EVENT_* or syscall stop
        if ((sig == SIGTRAP && event != 0) || (sig == (SIGTRAP | 0x80) && event == 0)) {
            return 0;
        }
        else {
            if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU) {
                siginfo_t info;
                int stopped = ptrace(PTRACE_GETSIGINFO, tracee, 0, &info) < 0 && errno == EINVAL;
                if (stopped) {
                    WARNING("Not implemented: group stop not handled");
                    return 1;
                }
                // signals that could also be a group stop
                DEBUG_MPK("pid %u received signal %d '%s', event %d", tracee, sig, strsignal(sig), event);
                return 0;
            }
            else if (sig == SIGSEGV) {
                DEBUG_MPK("pid %u received SEGFAULT %d '%s', event %d", tracee, sig, strsignal(sig), event);
                siginfo_t info;
                int ret = ptrace(PTRACE_GETSIGINFO, tracee, 0, &info);
                assert(0 == ret);
                DEBUG_MPK("segfaulting address: %p", info.si_addr);
                DEBUG_MPK("siginfo.code: %d", info.si_code);
                switch (info.si_code) {
                    case SEGV_MAPERR: DEBUG_MPK("mapping error"); break;
                    case SEGV_ACCERR: DEBUG_MPK("access error"); break;
                    case SEGV_PKUERR: DEBUG_MPK("pku error: %x", info.si_pkey); break;
                    case SEGV_BNDERR: DEBUG_MPK("bound error"); break;
                    default: DEBUG_MPK("unknown suberror"); break;
                }
                tracee_t *tracee_t_ = _get_tracee_by_pid(out_event->pid);
                _get_regs_generic(tracee_t_);
                DEBUG_MPK("RIP: %llx", tracee_t_->arch_regs.rip);
                return 0;
            }
            else {
                // all other signals
                DEBUG_MPK("pid %u received signal %d '%s', event %d", tracee, sig, strsignal(sig), event);
                return 0;
            }
        }
    }
    else {
        ERROR_FAIL("unrecognized waitpid status");
    }

    return 1;
}
//------------------------------------------------------------------------------

FORCE_INLINE void sf_ptrace_tracer_attach(pid_t tracee, int ptrace_options)
{
    int status;
    DEBUG_SF("Trying to attach ptrace tracer to tracee %d\n", tracee);
    if (tracee == -1) {
        ERROR_FAIL("could not clone");
    }

    // wait for child to signal itself
    if (waitpid(tracee, &status, 0) == -1) {
        perror("waitpid failed");
        ERROR_FAIL("tracee not available");
    }

    // kill tracee, if tracer dies; report syscalls with (SIGTRAP | 0x80); stop on clone syscalls
    if (ptrace(PTRACE_SETOPTIONS, tracee, NULL, ptrace_options) == -1) {
        ERROR_FAIL("failed to initialize tracing");
    }

    if (NUM_CORES >= 2) {
        // confine tracer to core 0
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(0, &set);
        assert(sched_setaffinity(getpid(), sizeof(cpu_set_t), &set) == 0);

        // confine tracee to core 1
        CPU_ZERO(&set);
        CPU_SET(1, &set);
        assert(sched_setaffinity(tracee, sizeof(cpu_set_t), &set) == 0);
    }
}
//------------------------------------------------------------------------------

FORCE_INLINE uint64_t* sf_ptrace_tracer_swap_stack_with_tracee(pid_t tracee) {
    size_t tix = 0;
    for (tix = 0; tix < NUM_THREADS; tix++) {
        if (pk_data.threads[tix] && 
            pk_data.threads[tix] != THREAD_EXITING &&
            pk_data.threads[tix]->gettid == tracee) {
            break;
        }
    }
    if (tix == NUM_THREADS) {
        ERROR_FAIL("could not find tracee thread");
    } else {
        DEBUG_SF("Found tracee thread at idx %zu", tix);
    }

    _pk_thread_domain* tracee_domain_data = &pk_data.threads[tix]->thread_dom_data[CURRENT_DID];
    _pk_thread_domain* tracer_domain_data = &_get_thread_data()->thread_dom_data[CURRENT_DID];

    // Give our current stack to tracee
    DEBUG_SF("Give our stack to tracee");
    tracee_domain_data->user_stack      = tracer_domain_data->user_stack;
    tracee_domain_data->user_stack_base = tracer_domain_data->user_stack_base;
    tracee_domain_data->user_stack_size = tracer_domain_data->user_stack_size;

    // Allocate a new stack for tracer
    DEBUG_SF("Allocate new tracer stack");
    tracer_domain_data->expected_return = 0;
    tracer_domain_data->user_stack_size = 0;
    tracer_domain_data->user_stack_base = 0;
    int ret = _allocate_user_stack(CURRENT_DID, tracer_domain_data);
    if(ret != 0){
        ERROR_FAIL("prepare_user_stack_pthread failed");
    }

    // Initialize new stack at its top
    tracer_domain_data->user_stack = (uint64_t*)GET_STACK_TOP(tracer_domain_data);
    return tracer_domain_data->user_stack;
}
//------------------------------------------------------------------------------

