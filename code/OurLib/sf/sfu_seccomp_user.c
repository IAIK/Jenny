#include "sf_internal.h"
#include "pk.h"
#include "pk_internal.h"
#include "common_seccomp.h"
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/seccomp.h>


/**
 *
 * WARNING:
 * Seccomp_user cannot filter syscalls, but can only emulate them.
 * This means all "filtered" and "allowed" syscalls are actually
 * executed in the context of the tracer, which is the monitor!
 *
 * Further, seccomp does only provide the syscalls registers in
 * seccomp_notif. There is no straightforward way to know in which domain
 * a syscall was executed or if it even was run in the monitor.
 * For the sake of benchmarking to compare seccomp_user with the other
 * tracing methods, we assume a single threaded tracee with Donky thread
 * ID 1. This way we can retrieve mentioned information about the tracee.
 *
 */

static int listener = -1;
pthread_mutex_t listener_lock;
pthread_cond_t listener_condition;

static void *_tracee_wrapper(void *arg)
{
    if (NUM_CORES >= 2) {
        // confine tracee to CPU core 1
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(1, &set);
        assert(sched_setaffinity(getpid(), sizeof(cpu_set_t), &set) == 0);
    }

    SET_THREAD_NAME(pthread_self(), "tracee");

    int ret = _register_bpf_type(SF_SECCOMP_USER);
    if (ret < 0) {
        ERROR_FAIL("could not register bpf");
    }

    DEBUG_SF("Notify tracer of new listener fd: %d", ret);
    assert(0 == pthread_mutex_lock(&listener_lock));
    listener = ret;
    assert(0 == pthread_cond_signal(&listener_condition));
    assert(0 == pthread_mutex_unlock(&listener_lock));

    DEBUG_SF("Done");

    // synchronize by calling syscall that must wait for tracer
    // (no fd to close, as folder cannot be opened with O_RDWR)
    // FILTER=none: no synchronization needed
    // FILTER=self: path sanitization filter
    // FILTER=extended-monitor: localstorage filter
    syscall(SYS_openat, AT_FDCWD, ".", O_RDWR);

    sf_tracee_function *start = (sf_tracee_function *)arg;
    exit(start->function(start->arg));
    return 0;
}
//------------------------------------------------------------------------------

void *_tracer_wrapper(void *arg)
{
    if (NUM_CORES >= 2) {
        // confine tracer to CPU core 0
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(0, &set);
        assert(sched_setaffinity(getpid(), sizeof(cpu_set_t), &set) == 0);
    }

    SET_THREAD_NAME(pthread_self(), "TRACER");

    DEBUG_SF("Waiting for seccomp-bpf to be installed");
    assert(0 == pthread_mutex_lock(&listener_lock));
    while (-1 == listener) {
        assert(0 == pthread_cond_wait(&listener_condition, &listener_lock));
    }
    assert(0 == pthread_mutex_unlock(&listener_lock));
    assert(-1 != listener);

    DEBUG_SF("Obtained new listener fd %d", listener);
    DEBUG_SF("Listening on it");
    pk_sysfilter_tracer(sf_seccomp_user_tracer, (pid_t)(uintptr_t)listener);
    return 0;
}
//------------------------------------------------------------------------------

int _sf_mechanism_seccomp_user(sf_tracee_function *start)
{
    DEBUG_SF("Initializing seccomp_user");
    assert(0 == pthread_mutex_init(&listener_lock, NULL));
    assert(0 == pthread_cond_init(&listener_condition, NULL));

    pthread_t tid_tracee, tid_tracer;
    assert(pk_pthread_create(&tid_tracee, NULL, _tracee_wrapper, start) == 0);
    assert(pk_pthread_create(&tid_tracer, NULL, _tracer_wrapper, NULL) == 0);

    SET_THREAD_NAME(pthread_self(), "main");
    //SET_THREAD_NAME(tid_tracee, "tracee");
    //SET_THREAD_NAME(tid_tracer, "TRACER");

    assert(pthread_join(tid_tracee, NULL) == 0);
    assert(pthread_cancel(tid_tracer) == 0);
    assert(pthread_join(tid_tracer, NULL) == 0);
    return 0;
}
//------------------------------------------------------------------------------

int _sf_mechanism_seccomp_user_ctor() {
    DEBUG_SF("Initializing seccomp_user");
    assert(0 == pthread_mutex_init(&listener_lock, NULL));
    assert(0 == pthread_cond_init(&listener_condition, NULL));

    pthread_t tid_tracer;
    // same tracer wrapper as without ctor
    assert(pk_pthread_create(&tid_tracer, NULL, _tracer_wrapper, NULL) == 0);

    SET_THREAD_NAME(pthread_self(), "main");
    //SET_THREAD_NAME(tid_tracer, "TRACER");

    // Install seccomp-bpf in current thread
    int ret = _register_bpf_type(SF_SECCOMP_USER);
    if (ret < 0) {
        ERROR_FAIL("could not register bpf");
    }

    // DO NOT DO ANY FILTERED SYSCALLS (debug output, etc)
    // UNTIL WE SIGNALLED THE TRACER THREAD
    
    // Notify tracer to listen on seccomp-bpf
    assert(0 == pthread_mutex_lock(&listener_lock));
    listener = ret;
    assert(0 == pthread_cond_signal(&listener_condition));
    assert(0 == pthread_mutex_unlock(&listener_lock));

    DEBUG_SF("Notified tracer of new listener fd: %d", ret);
    return 0;
}
//------------------------------------------------------------------------------
