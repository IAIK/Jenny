#include "sf_internal.h"
#include "common_ptrace.h"
#include "common_seccomp.h"
#include "pk.h"
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>


static void *_tracee_wrapper(void *arg)
{
    pid_t own_pid = getpid();
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        ERROR_FAIL("PTRACE_TRACEME");
    }
    kill(own_pid, SIGSTOP);

    // attach tracer before registering seccomp filters
    // as the seccomp filter is not installed, no PTRACE_EVENT_SECCOMP
    // are generated for the syscalls before in this function
    // -> can deny ptrace, kill syscalls
    if (_register_bpf_type(SF_PTRACE_DELEGATE) < 0) {
        ERROR_FAIL("could not register bpf");
    }
    sf_tracee_function *start = (sf_tracee_function *)arg;
    exit(start->function(start->arg));
    return 0;
}
//------------------------------------------------------------------------------

// this start function and the tracee wrapper can not already be PK_CODE
// as it is called only by root domain
int _sf_mechanism_ptrace_delegate(sf_tracee_function *start)
{
    start->wrapper = _tracee_wrapper;
    pid_t tracee = sf_start_tracee(start);

    return pk_sysfilter_tracer(sf_ptrace_delegate_tracer, tracee);
}
//------------------------------------------------------------------------------

PK_API void *_ptrace_delegate_tracee_wrapper_ctor(void *arg) {
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

    // attach tracer before registering seccomp filters
    // as the seccomp filter is not installed, no PTRACE_EVENT_SECCOMP
    // are generated for the syscalls before in this function
    // -> can deny ptrace, kill syscalls
    if (_register_bpf_type(SF_PTRACE_DELEGATE) < 0) {
        ERROR_FAIL("could not register bpf");
    }
    
    DEBUG_SF("Switching to stack %p", start->arg);
    DEBUG_SF("And dropping to main");
    return start->arg;
}
//------------------------------------------------------------------------------

#ifdef __x86_64__
 __attribute__((naked)) static void * _tracee_wrapper_ctor_asm(void *arg) {
    asm volatile(
      "addq $-8, %rsp\r\n"
      "call _ptrace_delegate_tracee_wrapper_ctor\r\n"
      "mov %rax, %rsp\r\n" // restore parent's stack pointer
      "movq $0, %rax\r\n"  // Prepare return value for _sf_mechanism_ptrace_delegate_ctor_asm
      "ret\r\n"            // ret will continue at the end of the tracer's ctor
                           // (i.e., the call site of _sf_mechanism_ptrace_delegate_ctor_asm)
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

int _sf_mechanism_ptrace_delegate_ctor(void* stack) {
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
    pk_sysfilter_tracer(sf_ptrace_delegate_tracer_ctor_asm, tracee);
    ERROR_FAIL("Should not reach here");
    return 0;
}
//------------------------------------------------------------------------------

#ifdef __x86_64__
 __attribute__((naked)) int _sf_mechanism_ptrace_delegate_ctor_asm() {
    asm volatile(
        "mov %rsp, %rdi\r\n"  // save original stack pointer
        "addq $-8, %rsp\r\n"
        "call _sf_mechanism_ptrace_delegate_ctor\r\n"
    );
}
//-------------------------------------------------------------------------------
#else
__attribute__((naked)) int _sf_mechanism_ptrace_delegate_ctor_asm() {
    ERROR_FAIL("implement me");
}
//-------------------------------------------------------------------------------
#endif
