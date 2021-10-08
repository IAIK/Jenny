#include "sf_internal.h"
#include "common_ptrace.h"
#include "pk.h"
#include <sched.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/audit.h>
#include <linux/ptrace.h>


static void *_tracee_wrapper(void *arg)
{
    pid_t own_pid = getpid();
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        ERROR_FAIL("PTRACE_TRACEME");
    }
    // signal self so parent knows, we started tracing
    kill(own_pid, SIGSTOP);
    sf_tracee_function *start = (sf_tracee_function *)arg;
    exit(start->function(start->arg));
    return 0;
}
//------------------------------------------------------------------------------

// this start function and the tracee wrapper can not already be PK_CODE
// as it is called only by root domain
int _sf_mechanism_ptrace(sf_tracee_function *start)
{
    start->wrapper = _tracee_wrapper;
    pid_t tracee = sf_start_tracee(start);

    return pk_sysfilter_tracer(sf_ptrace_tracer, tracee);
}
//------------------------------------------------------------------------------

/*
// Used for testing instead of stack switching
// However: Memory is not writable when doing a fork.
int _sf_mechanism_ptrace_ctor_fork() {
    pid_t tracee = fork();
    if (tracee) {
        // parent
        DEBUG_SF("ptrace parent running tracer");
        pk_sysfilter_tracer(sf_ptrace_tracer, tracee);
        exit(0);
        return 0;
    } else {
        // child
        DEBUG_SF("ptrace child signaling parent");
        pid_t own_pid = getpid();
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            ERROR_FAIL("PTRACE_TRACEME");
        }
        // signal self so parent knows, we started tracing
        kill(own_pid, SIGSTOP);
        return 0;
    }
}*/
//------------------------------------------------------------------------------

PK_API void *_tracee_wrapper_ctor(void *arg) {
    sf_tracee_function* start = (sf_tracee_function*)arg;

    SET_THREAD_NAME(pthread_self(), "tracee");

    pid_t own_pid = getpid();
    DEBUG_SF("Tracee preparing with TRACEME");
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        ERROR_FAIL("PTRACE_TRACEME");
    }
    // signal self so parent knows, we started tracing
    DEBUG_SF("Tracee signalling ourselves: pid %d", own_pid);
    kill(own_pid, SIGSTOP);
    DEBUG_SF("Tracee woke up");
    DEBUG_SF("Switching to stack %p", start->arg);
    DEBUG_SF("And dropping to main");
    return start->arg;
}
//------------------------------------------------------------------------------

#ifdef __x86_64__
 __attribute__((naked)) static void * _tracee_wrapper_ctor_asm(void *arg) {
    asm volatile(
      "addq $-8, %rsp\r\n"
      "call _tracee_wrapper_ctor\r\n"
      "mov %rax, %rsp\r\n" // restore parent's stack pointer
      "movq $0, %rax\r\n"  // Prepare return value for _sf_mechanism_ptrace_ctor_asm
      "ret\r\n"            // ret will continue at the end of the tracer's ctor
                           // (i.e., the call site of _sf_mechanism_ptrace_ctor_asm)
                           // and drop into main
    );
}
//------------------------------------------------------------------------------
#else
 __attribute__((naked)) static void * _tracee_wrapper_ctor_asm(void *arg) {
    ERROR_FAIL("implement me");
}
//-------------------------------------------------------------------------------
#endif

int _sf_mechanism_ptrace_ctor(void* stack) {
    DEBUG_SF("Ptracing: store original stack pointer %p\n", stack);
    sf_tracee_function start = {
      .function = NULL,
      .wrapper = _tracee_wrapper_ctor_asm,
      .arg = stack,
    };
    pid_t tracee = sf_start_tracee(&start);
    DEBUG_SF("Started tracee with tid %d\n", tracee);

    // Run tracer in monitor
    // and switch to a new stack such that our tracee can safely
    // reuse the original stack and drop into main
    // This function never returns
    pk_sysfilter_tracer(sf_ptrace_tracer_ctor_asm, tracee);
    ERROR_FAIL("Should not reach here");
    return 0;
}
//------------------------------------------------------------------------------

#ifdef __x86_64__
 __attribute__((naked)) int _sf_mechanism_ptrace_ctor_asm() {
    asm volatile(
        "mov %rsp, %rdi\r\n"  // save original stack pointer
        "addq $-8, %rsp\r\n"
        "call _sf_mechanism_ptrace_ctor\r\n"
    );
}
//-------------------------------------------------------------------------------
#else
__attribute__((naked)) int _sf_mechanism_ptrace_ctor_asm() {
    ERROR_FAIL("implement me");
}
//-------------------------------------------------------------------------------
#endif
