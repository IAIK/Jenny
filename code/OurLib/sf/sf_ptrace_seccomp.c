#include "sf_internal.h"
#include "common_ptrace.h"
#include "pk.h"
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>


/**
 * @brief Handles events from tracee to trace syscalls.
 *
 * @param e
 *          the event struct
 * @param threads_count
 *          pointer to threads counter
 *  * @return
 *          0
 *              if there is an actual syscall event (default codepath).
 *          1
 *              if there is any other event (clone event, signal)
 *
 */
static int _handle_syscall_event(event_t *e)
{
    if (e->signal == (SIGTRAP | 0x80) && e->event == 0) {
        return 0;
    }

    if (e->signal != SIGTRAP) {
        // redeploy other signal
        WARNING("expected SIGTRAP");
        ptrace(PTRACE_CONT, e->pid, NULL, e->signal);
        return 1;
    }

    // signal == SIGTRAP
    if (e->event == PTRACE_EVENT_CLONE) {
        unsigned long data;
        pid_t new_pid;
        event_t e1;

        if (ptrace(PTRACE_GETEVENTMSG, e->pid, NULL, &data) == -1) {
            ERROR_FAIL("PTRACE_GETEVENTMSG");
        }
        new_pid = (pid_t)data;

        // wait for clone to finish minding that process could have been killed inbetween
        if (_next_event(new_pid, &e1) != 0 || e1.signal != SIGSTOP || e1.event != 0) {
            WARNING("could not wait on cloned pid %d", new_pid);
            return 1;
        }
        DEBUG_SF("PTRACE_EVENT_CLONE from pid %u", new_pid);
        if (_add_tracee(new_pid) != 0) {
            ERROR_FAIL("too many threads");
        }

        if (ptrace(PTRACE_CONT, new_pid, NULL, NULL) == -1) {
            ERROR_FAIL("PTRACE_CONT new_pid");
        }

        // if no pre hook was executed (when clone is not actually filtered),
        // we do not want to get to the post hook
        tracee_t *tracee = _get_tracee_by_pid(e->pid);
        if (tracee->is_exit) {
            if (ptrace(PTRACE_SYSCALL, e->pid, NULL, NULL) == -1) {
                ERROR_FAIL("PTRACE_SYSCALL tracee");
            }
        }
        else {
            if (ptrace(PTRACE_CONT, e->pid, NULL, NULL) == -1) {
                ERROR_FAIL("PTRACE_CONT tracee");
            }
        }
        return 1;
    }
    else if (e->event == PTRACE_EVENT_SECCOMP) {
        return 0;
    }
    else {
        ERROR_FAIL("unknown ptrace event");
        return 1;
    }
}

int PK_API PK_CODE sf_ptrace_seccomp_tracer(pid_t tracee)
{
    // kill tracee; report syscalls with (SIGTRAP | 0x80); stop on seccomp events, stop on clone syscalls
    sf_ptrace_tracer_attach(tracee, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);

    return sf_ptrace_seccomp_tracer_loop(tracee);
}
//-------------------------------------------------------------------------------

// In the ctor case we need to switch stacks
PK_API void* PK_CODE sf_ptrace_seccomp_tracer_ctor(pid_t tracee)
{
    // kill tracee; report syscalls with (SIGTRAP | 0x80); stop on seccomp events, stop on clone syscalls
    sf_ptrace_tracer_attach(tracee, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);

    return sf_ptrace_tracer_swap_stack_with_tracee(tracee);
}
//-------------------------------------------------------------------------------

#ifdef __x86_64__
 __attribute__((naked)) int PK_API PK_CODE sf_ptrace_seccomp_tracer_ctor_asm(pid_t tracee) {
    asm volatile(
        "push %rdi\r\n"
        "call sf_ptrace_seccomp_tracer_ctor\r\n"
        "pop %rdi\r\n" // restore tracee argument
        "mov %rax, %rsp\r\n"
        "call sf_ptrace_seccomp_tracer_loop\r\n"
        "mov %rax, %rdi\r\n"
        "call exit\r\n"
    );
}
//-------------------------------------------------------------------------------

#else
__attribute__((naked)) int PK_API PK_CODE sf_ptrace_seccomp_tracer_ctor_asm(pid_t tracee) {
    ERROR_FAIL("implement me");
}
#endif
//-------------------------------------------------------------------------------

int PK_API PK_CODE sf_ptrace_seccomp_tracer_loop(pid_t tracee_pid)
{
    if (ptrace(PTRACE_CONT, tracee_pid, NULL, NULL) == -1) {
        ERROR_FAIL("failed to release tracee");
    }
    // Now child is released for the first time
    // In case of ctor, it is reusing our original stack and dropping to main in
    // _tracee_wrapper_ctor_asm

    assert(_add_tracee(tracee_pid) == 0);

    while (1) {
        event_t e;

        // end tracing when there are no processes left
        if (tracees_count == 0) {
            break;
        }

        // get next ptrace event (signal from any tracee) and handle it
        if (_next_event(-1, &e) != 0
                || _handle_syscall_event(&e) != 0) {
            continue;
        }

        tracee_t *tracee = _get_tracee_by_pid(e.pid);
        if (tracee == NULL) {
            ERROR_FAIL("pid %u not registerd", e.pid);
        }

        if (!tracee->is_exit) {
            DEBUG_SF("sysenter (PTRACE_EVENT_SECCOMP) from pid %u", tracee->pid);

            _handle_enter_syscall_sameprocess(tracee);
            tracee->is_exit = true;

            if (ptrace(PTRACE_SYSCALL, tracee->pid, NULL, NULL) == -1) {
                ERROR_FAIL("PTRACE_SYSCALL");
            }
        }
        else {
            DEBUG_SF("sysexit (SIGTRAP) from pid %u", tracee->pid);

            _handle_exit_syscall(tracee);
            tracee->is_exit = false;

            if (ptrace(PTRACE_CONT, tracee->pid, NULL, NULL) == -1) {
                ERROR_FAIL("PTRACE_CONT");
            }
        }
    }
    return 0;
}
//------------------------------------------------------------------------------
