#include "sf_internal.h"
#include "tcb.h" // struct pthread
//#include "pk_debug.h"
//#include "pk.h"
//#include "pthread.h"
#include <inttypes.h>

//------------------------------------------------------------------------------
// SF data structures:
_sf_data PK_API sf_data = {0,};

//------------------------------------------------------------------------------

void _get_config(int *mechanism, int *filter)
{
    // proxy kernel can only operate with mechanism "usermode"
#ifdef PROXYKERNEL
    *mechanism = SF_USERMODE;
    *filter = SF_SELF;
#endif

    *mechanism = SF_NONE;
    char* mech = getenv("MECHANISM");
    if (!mech) {
        ERROR("No MECHANISM environment variable specified");
        ERROR_FAIL("Choose one of {none,ptrace,ptrace_seccomp,ptrace_delegate,seccomp,seccomp_user,usermode,indirect,sysmodule}");
    }
    if (strcmp(mech, "none") == 0) {
        *mechanism = SF_NONE;
    } else if (strcmp(mech, "ptrace") == 0) {
        *mechanism = SF_PTRACE;
    } else if (strcmp(mech, "ptrace_seccomp") == 0) {
        *mechanism = SF_PTRACE_SECCOMP;
    } else if (strcmp(mech, "ptrace_delegate") == 0) {
        *mechanism = SF_PTRACE_DELEGATE;
    } else if (strcmp(mech, "seccomp") == 0) {
        *mechanism = SF_SECCOMP;
    } else if (strcmp(mech, "seccomp_user") == 0) {
        *mechanism = SF_SECCOMP_USER;
    } else if (strcmp(mech, "usermode") == 0) {
        *mechanism = SF_USERMODE;
#ifdef __x86_64__
    } else if (strcmp(mech, "indirect") == 0) {
        *mechanism = SF_INDIRECT;
    } else if (strcmp(mech, "sysmodule") == 0) {
        *mechanism = SF_SYSMODULE;
#endif
    } else {
        ERROR("Invalid MECHANISM environment variable: %s", mech);
        ERROR_FAIL("Choose one of {none,ptrace,ptrace_seccomp,ptrace_delegate,seccomp,seccomp_user,usermode,indirect,sysmodule}");
    }

    const char* invalid_filter_error_message = "Choose one of {none,self-donky,localstorage} DEPRECATED: {old-self,old-self-open,old-extended-domain}";

    *filter = SF_NONE;
    char* filt = getenv("FILTER");
    if (!filt) {
        ERROR("No FILTER environment variable specified");
        ERROR_FAIL("%s", invalid_filter_error_message);
    }
    if (strcmp(filt, "none") == 0) {
        *filter = SF_NONE;
    } else if (strcmp(filt, "just-domain") == 0) {
        *filter = SF_JUST_DOMAIN;
    }


    else if (strcmp(filt, "self-donky") == 0) {
        *filter = SF_SELF_DONKY;
    }else if (strcmp(filt, "self-mpk") == 0) {
        *filter = SF_SELF_MPK;
    } else if (strcmp(filt, "localstorage") == 0) {
        *filter = SF_EXTENDED_MONITOR;
    }


    //old:
    else if (strcmp(filt, "old-self") == 0) {
        *filter = SF_SELF;
    } else if (strcmp(filt, "old-self-open") == 0) {
        *filter = SF_SELF_OPEN;
    //} else if (strcmp(filt, "old-self-prctl") == 0) {
    //    *filter = SF_SELF_PRCTL;
    } else if (strcmp(filt, "old-extended-domain") == 0) { //still used for microbenchmarks
        *filter = SF_EXTENDED_DOMAIN;
    } else if (strcmp(filt, "nginx") == 0) {
        *filter = SF_SELF_MPK; //act as if this is just self-mpk. do the rest in nginx
    } else {
        ERROR("Invalid FILTER environment variable: %s", filt);
        ERROR_FAIL("%s", invalid_filter_error_message);
    }
}
//------------------------------------------------------------------------------

extern void ecall_sf_root_domain_init(int mechanism, int filter, int child);
extern void _ecall_receive_sf_root_domain_init(int mechanism, int filter, int child);

void PK_API sf_root_domain_init(int mechanism, int filter, int child) {
    DEBUG_MPK("root domain using mechanism %d installing domain filters %d for child %d", mechanism, filter, child);
    sf_filters_init(mechanism, filter);
    sf_localstorage_filters_init(child);
}
//------------------------------------------------------------------------------

void sf_pk_filters_init(int mechanism, int filter) {
    int init_flags = mechanism == SF_SYSMODULE ? PK_SYSMODULE : 0;

    if (filter == SF_EXTENDED_DOMAIN || filter == SF_JUST_DOMAIN) {
        int child = pk_init(init_flags | PK_DROP_CHILD, &_ecall_receive_sf_root_domain_init, ECALL_ROOT_DOMAIN_INIT_ID);
        if(child < 0){
            ERROR_FAIL("pk_init failed");
        }
        domain_of_main = child;
        ecall_sf_root_domain_init(mechanism, filter, child);
    } else if (filter == SF_EXTENDED_MONITOR) {
        if(pk_init(init_flags, NULL, NULL) != 0){
            ERROR_FAIL("pk_init failed");
        }
        sf_filters_init(mechanism, filter);
        sf_localstorage_filters_init(-1);
    } else {
        if(pk_init(init_flags, NULL, NULL) != 0){
            ERROR_FAIL("pk_init failed");
        }
        sf_filters_init(mechanism, filter);
    }
}
//------------------------------------------------------------------------------

int PK_API sf_init(sf_tracee_function *start)
{
    int mechanism, filter;
    _get_config(&mechanism, &filter);
    sf_data.sf_mechanism_current = mechanism;
    sf_data.sf_filter_current = filter;

    //if (mechanism != SF_NONE){
        sf_pk_filters_init(mechanism, filter);
    //}

    int ret = -1;
    switch (mechanism) {
        case SF_SECCOMP:
            ret = _sf_mechanism_seccomp(start);
        break;
        case SF_PTRACE:
            ret = _sf_mechanism_ptrace(start);
        break;
        case SF_PTRACE_SECCOMP:
            ret = _sf_mechanism_ptrace_seccomp(start);
        break;
        case SF_PTRACE_DELEGATE:
            ret = _sf_mechanism_ptrace_delegate(start);
        break;
        case SF_SECCOMP_USER:
            ret = _sf_mechanism_seccomp_user(start);
        break;
        case SF_USERMODE: {
#ifdef __riscv
            ret = start->function(start->arg);
#else
            ERROR_FAIL("SF_USERMODE not supported by x86_64");
#endif
        }
        break;
        case SF_INDIRECT: {
#ifdef __x86_64__
            ret = start->function(start->arg);
#else
            ERROR_FAIL("SF_INDIRECT not supported by riscv");
#endif
        }
        break;
        case SF_NONE:
        default:
            ret = start->function(start->arg);
    }
    return ret;
}
//------------------------------------------------------------------------------

#ifdef CONSTRUCTOR

FILE* ftiming = NULL;
int ftiming_pid = 0;
uint64_t timing_ctor = 0;
uint64_t timing_dtor = 0;

__attribute__((constructor(105)))
void sf_self_init_ctor()
{
    DEBUG_MPK("Initializing syscall filters according to environment variables");
    char* file = getenv("FILE");
    if (file) {
        DEBUG_MPK("Will append timing results to %s", file);
        ftiming = fopen(file, "a");
        if (!ftiming) {
            perror("fopen failed");
            ERROR_FAIL("Could not open FILE %s", file);
        }
    }

    int mechanism, filter;
    _get_config(&mechanism, &filter);
    sf_data.sf_mechanism_current = mechanism;
    sf_data.sf_filter_current = filter;

    sf_pk_filters_init(mechanism, filter);

    int ret = -1;
    switch (mechanism) {
        case SF_SECCOMP:
            ret = _sf_mechanism_seccomp_ctor();
        break;
        case SF_PTRACE:
            ret = _sf_mechanism_ptrace_ctor_asm();
        break;
        case SF_PTRACE_SECCOMP:
            ret = _sf_mechanism_ptrace_seccomp_ctor_asm();
        break;
        case SF_PTRACE_DELEGATE:
            ret = _sf_mechanism_ptrace_delegate_ctor_asm();
        break;
        case SF_SECCOMP_USER:
            ret = _sf_mechanism_seccomp_user_ctor();
        break;
        case SF_USERMODE:
            ret = 0;
        break;
        case SF_INDIRECT:
        case SF_NONE:
        default:
            ret = 0;
    }

    // Since PTRACE methods do a stack swap between the tracer and the tracee
    // process, we need to obtain the pid afterwards, here:
    ftiming_pid = getpid();

    if (ret != 0) {
        ERROR_FAIL("Failed to setup syscall filter");
    }

    timing_ctor = RDTSC();
}
//------------------------------------------------------------------------------

__attribute__((destructor(9999)))
void sf_self_deinit() {
    DEBUG_MPK("Finalizing syscall filters");
    timing_dtor = RDTSC();
    assert(timing_dtor > timing_ctor);
    if (ftiming && ftiming_pid == getpid()) {
        FPRINTF_RESULTS(ftiming, "%s;%s;%" PRIu64 ";", getenv("MECHANISM"), getenv("FILTER"), timing_dtor - timing_ctor);
    }
}
//------------------------------------------------------------------------------

#endif // CONSTRUCTOR

pid_t PK_API sf_clone(void *(*function)(void *), void *arg)
{
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    assert(pthread_attr_setscope(&attr, PTHREAD_SCOPE_PROCESS) == 0);
    assert(pk_pthread_create(&thread, &attr, function, arg) == 0);

    SET_THREAD_NAME(pthread_self(), "TRACER");

    struct pthread *pd = (struct pthread *)thread;
    DEBUG_SF("Started tracee process with pid %d\n", pd->tid);
    return pd->tid;
}
//------------------------------------------------------------------------------

pid_t PK_API sf_start_tracee(sf_tracee_function *start)
{
    return sf_clone(start->wrapper, start);
}
//------------------------------------------------------------------------------

void PK_CODE _sfu_empty_filter(trace_info_t *ti) {
    DEBUG_FILTER();
}
//------------------------------------------------------------------------------


