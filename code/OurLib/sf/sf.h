#pragma once
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
//#define GNU_SOURCE 1
#include "pk.h"

//------------------------------------------------------------------------------
// SF API Defines
//------------------------------------------------------------------------------
#define SYSCALL_ALLOWED         (void *)-1
#define SYSCALL_DENIED          (void *)-2
#define SYSCALL_UNSPECIFIED     (void *)-3
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// Initialization
//------------------------------------------------------------------------------

#define SYS_SET_SEDELEG (258)
#define MASK_CAUSE_MPKEY_MISMATCH (1UL << 0xe)
#define MASK_CAUSE_USER_ECALL (1UL << 0x8)
#define MASK_CAUSE_BOTH (MASK_CAUSE_MPKEY_MISMATCH | MASK_CAUSE_USER_ECALL)

#ifndef __x86_64__
#define ENABLE_SYSCALL_DELEGATION() assert(syscall(SYS_SET_SEDELEG, MASK_CAUSE_BOTH) == 0)
#define DISABLE_SYSCALL_DELEGATION() assert(syscall(SYS_SET_SEDELEG, MASK_CAUSE_MPKEY_MISMATCH) == 0)
#else
#define ENABLE_SYSCALL_DELEGATION() do { } while(0)
#define DISABLE_SYSCALL_DELEGATION() do { } while(0)
#endif

#define SF_NONE            0
#define SF_PTRACE          1
#define SF_PTRACE_SECCOMP  2
#define SF_PTRACE_DELEGATE 3
#define SF_SECCOMP         4
#define SF_SECCOMP_USER    5
#define SF_USERMODE        6
#define SF_INDIRECT        7
#define SF_SYSMODULE       8
#define SF_MECHANISMS      9  // always one more than highest

//NOTE: 0 is the same as the above SF_NONE
#define SF_SELF_DONKY           1
#define SF_SELF_MPK             2
#define SF_EXTENDED_MONITOR     3
#define SF_SELF                 4  // DEPRECATED
#define SF_SELF_OPEN            5  // DEPRECATED
#define SF_EXTENDED_DOMAIN      6  // DEPRECATED but still used for benchmarking
#define SF_JUST_DOMAIN          7  // just for benchmarking
#define SF_FILTERS              8  // always one more than highest


/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/
#include "sysent.h"  // STRACE
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/user.h>
#include <stdatomic.h>

#ifndef __x86_64__
#include <asm/ptrace.h>
#endif

//#include "common_filters.h"

//------------------------------------------------------------------------------

// maximum number of file descriptors
#define NUM_FDS                       1024

typedef struct _sf_data {
    int sf_mechanism_current;
    int sf_filter_current;
    int sf_filters_initialized;
    atomic_int fd_domain_mapping[NUM_FDS]; // array containing information, about who owns a file descriptor
} _sf_data;
extern _sf_data sf_data; // Global sf data
//extern atomic_int fd_domain_mapping[NUM_FDS]; // Global sf data

//------------------------------------------------------------------------------
#define FD_DOMAIN_ANY              -1
#define FD_DOMAIN_NONE_OR_CLOSED    0

//------------------------------------------------------------------------------


typedef struct sf_tracee_function {
    int (*function)(void *);
    void *arg;
    void *(*wrapper)(void *);
} sf_tracee_function;


extern __thread int _sf_impersonate;

typedef int (*tracer_t)(pid_t);
int PK_API sf_init(sf_tracee_function *start);
ssize_t PK_API sf_write_results(int fd, const void *buf, size_t count);

PK_API int   sf_ptrace_tracer(pid_t tracee);
PK_API int   sf_ptrace_tracer_ctor_asm(pid_t tracee);
PK_API void* sf_ptrace_tracer_ctor(pid_t tracee);
PK_API int   sf_ptrace_tracer_loop(pid_t tracee);
PK_API int   sf_ptrace_seccomp_tracer(pid_t tracee);
PK_API int   sf_ptrace_seccomp_tracer_ctor_asm(pid_t tracee);
PK_API void* sf_ptrace_seccomp_tracer_ctor(pid_t tracee);
PK_API int   sf_ptrace_seccomp_tracer_loop(pid_t tracee);
PK_API int   sf_ptrace_delegate_tracer(pid_t tracee);
PK_API int   sf_ptrace_delegate_tracer_ctor_asm(pid_t tracee);
PK_API void* sf_ptrace_delegate_tracer_ctor(pid_t tracee);
PK_API int   sf_ptrace_delegate_tracer_loop(pid_t tracee);
PK_API int   sf_seccomp_user_tracer(pid_t tracee);

//------------------------------------------------------------------------------
// Functions and defines used for and in (monitor/domain) filters
//------------------------------------------------------------------------------

#define SYSCALL_ARG_COUNT         6
#define TI_INSYSCALL              1
#define TI_DENIED                 2
#define TI_FILTERED               4
#define TI_ARGS_COPY              8

#define IS_SYSCALL_DENIED(ti)       ((ti)->flags & TI_DENIED)
#define IS_SYSCALL_ALLOWED(ti)      (!IS_SYSCALL_DENIED(ti))
#define IS_SYSCALL_FILTERED(ti)     ((ti)->flags & TI_FILTERED)

#define SET_SYSCALL_DENIED(ti)      do { (ti)->flags |= TI_DENIED;          } while (0)
#define SET_SYSCALL_ALLOWED(ti)     do { (ti)->flags &= ~TI_DENIED;         } while (0)
#define SET_SYSCALL_FILTERED(ti)    do { (ti)->flags |= TI_FILTERED;        } while (0)
#define UNSET_SYSCALL_FILTERED(ti)  do { (ti)->flags &= ~TI_FILTERED;       } while (0)

#define IS_SYSCALL_EXIT(ti)         ((ti)->flags & TI_INSYSCALL)
#define IS_SYSCALL_ENTER(ti)        (!IS_SYSCALL_EXIT(ti))

#define SET_SYSCALL_ENTER(ti)       do { ((ti)->flags &= ~TI_INSYSCALL);    } while (0)
#define SET_SYSCALL_EXIT(ti)        do { ((ti)->flags |= TI_INSYSCALL);     } while (0)


#define SYSFILTER_RETURN(ti, ret)   do { SET_SYSCALL_DENIED(ti); (ti)->return_value = (ret); return; } while (0)


struct trace_info_t;
typedef void (*filter_t)(struct trace_info_t *ti);

typedef struct __attribute__((packed)) trace_info_t {
    int flags;                          // TI flags
    int did;                            // did from which the syscall was requested (= tracee/filteree)

    long syscall_nr;                    // requested syscall nr
    long args[SYSCALL_ARG_COUNT];       // (possibly modified) args of the requested syscall
    long orig_args[SYSCALL_ARG_COUNT];  // (the content of modified) args of the requested syscall
    long return_value;                  // return value (set by tracer)
    filter_t filter;                    // current filter

    void *mem;
    size_t mem_offset;
    uintptr_t padding;
} trace_info_t;

C_STATIC_ASSERT((sizeof(trace_info_t) % 16) == 8);

#define ARGS_MEM_SIZE (PAGESIZE*5)

pid_t PK_API sf_start_tracee(sf_tracee_function *start);


int  sf_localstorage_filters_init(int did);
void sf_filters_init(int mechanism, int filter);


typedef struct {
    uint8_t type;                       // how the argument should be copied into the args page
    uint8_t length;                     // length of the argument (ARG_TYPE_*_LEN) or the argument that holds
                                        // the length (ARG_TYPE_*)
} arg_copy_t;

/**
 * @brief Register syscall filter for child domain or monitor
 *
 * Registers a syscall @p filter that is called, when a syscall with number
 * @p sys_nr is called instead of the actual syscall for child domain @p did.
 *
 * @param did
 *        child domain, for which the should registerd
 * @param sys_nr
 *        syscall number, for which filter should be called
 * @param filter
 *        filter that should be called instead of the actual syscall
 * @param arg_copy
 *        array, of argument type and length for copying
 * @return
 *        0 on sucess, or -1 on error
 *
 */
int pk_sysfilter_domain(int did, int sys_nr, filter_t filter, arg_copy_t arg_copy[]);
int pk_sysfilter_monitor(int sys_nr, filter_t filter, arg_copy_t arg_copy[]);

/**
 * @brief Start a syscall tracer thread (e.g. ptrace, ptrace_seccomp, ...)
 * in context of the monitor.
 *
 * Function @p tracer is executed inside of an API call, therefore in the monitor.
 * This API function can be executed only once from the root domain. Subsequent
 * calls will result in an error.
 *
 * @param tracer
 *        function pointer to function to be executed
 * @param tracee
 *        pid to process that should be traced
 * @return
 *        0 on sucess, or -1 on error
 *
 */
int pk_sysfilter_tracer(tracer_t tracer, pid_t tracee);


//------------------------------------------------------------------------------
// Syscall table
//------------------------------------------------------------------------------

// Define it as compile-time constant, since sizeof(sf_table) / sizeof(sysent_t)
// can only be resolved in tracing.c. We statically assert this in tracing.c
#define NUM_MONITOR_FILTERS NUM_DOMAIN_FILTERS

#define ARG_TYPE_NONE                   0  // no copying for arg
#define ARG_TYPE_COPY                   1  // copy arg with given length
#define ARG_TYPE_COPY_ARGLEN            2  // copy arg with lenght given in other arg
#define ARG_TYPE_STR_COPY               3  // copy string in arg
#define ARG_TYPE_ALLOC_RESTORE          4  // allocate memory for arg with given length
#define ARG_TYPE_ALLOC_RESTORE_ARGLEN   5  // allocate memory for arg with length given in other arg
#define ARG_TYPE_CHECK                  6  // check, if domain can access arg with given length
#define ARG_TYPE_CHECK_ARGLEN           7  // check, if domain can access arg with length given in other arg
#define ARG_TYPES                       8

#define ARG_COPY_PATH_0                 {{ARG_TYPE_STR_COPY, 0}}
#define ARG_COPY_PATH_1                 {{0}, {ARG_TYPE_STR_COPY, 0}}
#define ARG_COPY_PATH_0_PATH_1          {{ARG_TYPE_STR_COPY, 0}, {ARG_TYPE_STR_COPY, 0}}
#define ARG_COPY_PATH_1_PATH_3          {{0}, {ARG_TYPE_STR_COPY, 0}, {0}, {ARG_TYPE_STR_COPY, 0}}

typedef struct {
    unsigned nargs;                             // number of args
    int sys_flags;                              // flags characterizing syscall
    filter_t filter;                            // pointer to filtering function taking a trace_info_t struct
    const char *sys_name;                       // name of syscall
    arg_copy_t arg_copy[SYSCALL_ARG_COUNT];     // how to do argument copying                                   
} sysent_t;

// We give read-only access to the monitor-protected sf_table
#define sf_table_unprotected sf_table

// table of monitor filters
extern sysent_t sf_table[];

//------------------------------------------------------------------------------
// Inline functions
//------------------------------------------------------------------------------

FORCE_INLINE void *sf_arg_alloc_native(trace_info_t *ti, size_t size)
{
    assert_ifdebug(ti->mem != NULL);
    size_t remaining = ARGS_MEM_SIZE - ti->mem_offset;
    if (size > remaining) {
        errno = ENOMEM;
        ERROR_FAIL("not enough memory for syscall argument, %zu", size);
    }
    void *mem = (void*)((uintptr_t)ti->mem + (uintptr_t)ti->mem_offset);
    ti->mem_offset += size;
    return mem;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// Debugging
//------------------------------------------------------------------------------

FORCE_INLINE const char * mechanism_str(int mechanism)
{
    if(mechanism >= SF_MECHANISMS || mechanism < 0){
        mechanism = SF_MECHANISMS;
    }

    static const char * mechanisms[SF_MECHANISMS+1] = {
        [SF_NONE]             = "SF_NONE",
        [SF_PTRACE]           = "SF_PTRACE",
        [SF_PTRACE_SECCOMP]   = "SF_PTRACE_SECCOMP",
        [SF_PTRACE_DELEGATE]  = "SF_PTRACE_DELEGATE",
        [SF_SECCOMP]          = "SF_SECCOMP",
        [SF_SECCOMP_USER]     = "SF_SECCOMP_USER",
        [SF_USERMODE]         = "SF_USERMODE",
        [SF_SYSMODULE]        = "SF_SYSMODULE",
        [SF_INDIRECT]         = "SF_INDIRECT",
        [SF_MECHANISMS]       = "__UNDEFINED__",
    };

    return mechanisms[mechanism];
}

FORCE_INLINE const char * filter_str(int filter)
{
    if(filter >= SF_FILTERS || filter < 0){
        filter = SF_FILTERS;
    }

    static const char * filters[SF_FILTERS+1] = {
        [SF_NONE]             = "SF_NONE",
        [SF_SELF]             = "SF_SELF",
        [SF_SELF_OPEN]        = "SF_SELF_OPEN",
        [SF_SELF_DONKY]       = "SF_SELF_DONKY",
        [SF_SELF_MPK]         = "SF_SELF_MPK",
        [SF_EXTENDED_MONITOR] = "SF_EXTENDED_MONITOR",
        [SF_EXTENDED_DOMAIN]  = "SF_EXTENDED_DOMAIN",
        [SF_JUST_DOMAIN]      = "SF_JUST_DOMAIN",
        [SF_FILTERS]          = "__UNDEFINED__",
    };

    return filters[filter];
}

/*
FORCE_INLINE const char * syscall_filter_str(int filter_or_function)
{
    if(filter_or_function == SYSCALL_ALLOWED){
        return "SYSCALL_ALLOWED";
    }else if(filter_or_function == SYSCALL_DENIED){
        return "SYSCALL_DENIED";
    }else if(filter_or_function == SYSCALL_UNSPECIFIED){
        return "SYSCALL_UNSPECIFIED";
    }else if(filter_or_function <= 0){
        return "__INVALID__";
    }else {
        return "CUSTOM";
    }
}
*/

FORCE_INLINE const char * sysent_to_syscall_str(sysent_t * sysent)
{
    return sysent->sys_name;
}

FORCE_INLINE const char * sysno_to_str(long sysno)
{
    assert(sysno >= 0);
    assert(sysno < (long)NUM_MONITOR_FILTERS);
    return sf_table_unprotected[sysno].sys_name;
}

FORCE_INLINE const char * sysent_flags_str(int flags)
{
    static char buf[128];
    int len = 0;

    len += sprintf(buf+len, flags & TRACE_DESC                  ? "TD,"   : "");
    len += sprintf(buf+len, flags & TRACE_FILE                  ? "TF,"   : "");
    len += sprintf(buf+len, flags & TRACE_IPC                   ? "TI,"   : "");
    len += sprintf(buf+len, flags & TRACE_NETWORK               ? "TN,"   : "");
    len += sprintf(buf+len, flags & TRACE_PROCESS               ? "TP,"   : "");
    len += sprintf(buf+len, flags & TRACE_SIGNAL                ? "TS,"   : "");
    len += sprintf(buf+len, flags & TRACE_MEMORY                ? "TM,"   : "");
    len += sprintf(buf+len, flags & TRACE_STAT                  ? "TST,"  : "");
    len += sprintf(buf+len, flags & TRACE_LSTAT                 ? "TLST," : "");
    len += sprintf(buf+len, flags & TRACE_FSTAT                 ? "TFST," : "");
    len += sprintf(buf+len, flags & TRACE_STAT_LIKE             ? "TSTA," : "");
    len += sprintf(buf+len, flags & TRACE_STATFS                ? "TSF,"  : "");
    len += sprintf(buf+len, flags & TRACE_FSTATFS               ? "TFSF," : "");
    len += sprintf(buf+len, flags & TRACE_STATFS_LIKE           ? "TSFA," : "");
    len += sprintf(buf+len, flags & TRACE_PURE                  ? "PU,"   : "");
    len += sprintf(buf+len, flags & SYSCALL_NEVER_FAILS         ? "NF,"   : "");
    //len += sprintf(buf+len, flags & MAX_ARGS                    ? "MA,"   : "");
    len += sprintf(buf+len, flags & MEMORY_MAPPING_CHANGE       ? "SI,"   : "");
    len += sprintf(buf+len, flags & STACKTRACE_CAPTURE_ON_ENTER ? "SE,"   : "");
    len += sprintf(buf+len, flags & COMPAT_SYSCALL_TYPES        ? "CST,"  : "");
    len += sprintf(buf+len, flags & TRACE_SECCOMP_DEFAULT       ? "TSD,"  : "");
    len += sprintf(buf+len, flags & TRACE_CREDS                 ? "TC,"   : "");
    len += sprintf(buf+len, flags & TRACE_CLOCK                 ? "TCL,"  : "");

    if(!len){
        len = 1;
    }
    buf[len-1] = '\0'; //strip away last delimiter

    assert((size_t)len < sizeof(buf));
    return buf;
}

FORCE_INLINE char * sf_trace_info_to_str(trace_info_t * ti, int summary){
    static char buf[256];
    int len = 0;
    assert(ti);
    assert(ti->syscall_nr >= 0 && ti->syscall_nr < NUM_MONITOR_FILTERS);

    sysent_t * sysent = &sf_table_unprotected[ti->syscall_nr];
    assert(sysent->nargs <= SYSCALL_ARG_COUNT);

    char * _pad = "  ";
    char * _endl = "\n";
    if(summary){
        _pad = "";
        _endl = ", ";
    }

    #define p(FMT, ...) sprintf(buf+len, "%s"FMT"%s", _pad, ##__VA_ARGS__, _endl);
    #define p2(FMT, ...) sprintf(buf+len, "%s"FMT, _pad, ##__VA_ARGS__);
    #define p3(FMT, ...) sprintf(buf+len, FMT"%s", ##__VA_ARGS__, _endl);

    len += p3("{ ");

    len += p(".flags = 0x%x", ti->flags);
    len += p(".did = %d", ti->did);
    len += p(".syscall_nr = %zu = %s", ti->syscall_nr, sysno_to_str(ti->syscall_nr));
    if(sysent->nargs){
        len += p2(".args = { ");
        for (size_t i = 0; i < SYSCALL_ARG_COUNT; i++)
        {
            len += p2("0x%zx ", ti->args[i]);
        }
        len += p3("}");
    }
    len += p(".return_value = 0x%zx", ti->return_value);
    len += p(".filter = 0x%zx", (uint64_t)ti->filter);
    len += sprintf(buf+len, "}");

    #undef p
    #undef p2
    #undef p3

    assert((size_t)len < sizeof(buf));
    return buf;
}
//------------------------------------------------------------------------------

FORCE_INLINE const char * arg_type_str(int type)
{
    if(type >= ARG_TYPES || type < 0){
        type = ARG_TYPES;
    }

    static const char * types[ARG_TYPES+1] = {
        [ARG_TYPE_NONE]                 = "NONE",
        [ARG_TYPE_COPY]                 = "COPY",
        [ARG_TYPE_COPY_ARGLEN]          = "COPY_ARGLEN",
        [ARG_TYPE_STR_COPY]             = "STR_COPY",
        [ARG_TYPE_ALLOC_RESTORE]        = "ALLOC_RESTORE",
        [ARG_TYPE_ALLOC_RESTORE_ARGLEN] = "ALLOC_RESTORE_ARGLEN",
        [ARG_TYPE_CHECK]                = "CHECK",
        [ARG_TYPE_CHECK_ARGLEN]         = "CHECK_ARGLEN",
        [ARG_TYPES]                     = "__UNDEFINED__"
    };

    return types[type];
}
//------------------------------------------------------------------------------

FORCE_INLINE const char * arg_copy_str(arg_copy_t *arg_copy)
{
    if (arg_copy == NULL) {
        return "(NONE)";
    }
    static char buf[512];
    int len = 0;
    for (int pos = 0; pos < SYSCALL_ARG_COUNT; pos++) {
        len += sprintf(buf+len, "(%s, %d),", arg_type_str(arg_copy[pos].type), arg_copy[pos].length);
    }
    return buf;
}
//------------------------------------------------------------------------------

#define DEBUG_FILTER() \
    do {\
        PREPEND_TO_DEBUG_BUFFER("%s %s:%d %s(...) (current did = %d, filteree = %d)\n", \
            IS_SYSCALL_ENTER(ti) ? "ENTER" : "EXIT", \
            __FILE__, __LINE__ , __FUNCTION__, \
            DID_INVALID /*pk_current_did() cannot call api function here. we may already be in a monitor filter.*/, \
            ti->did); \
        if (!IS_SYSCALL_ENTER(ti)) { PREPEND_TO_DEBUG_BUFFER("%s\n", sf_trace_info_to_str(ti, 0)); } \
        /*pk_print_current_reg();*/ \
    } while (0)
//------------------------------------------------------------------------------
#define DEBUG_FILTER_2() do{ PREPEND_TO_DEBUG_BUFFER("%s\n", sf_trace_info_to_str(ti, 0)); } while (0)
//------------------------------------------------------------------------------

#define FPRINTF_RESULTS(FILE, MESSAGE, ...) \
    do { \
        char buf[1024]; \
        ssize_t size = snprintf(buf, sizeof(buf), MESSAGE, ##__VA_ARGS__); \
        assert(size <= sizeof(buf)); \
        assert(sf_write_results(fileno(FILE), buf, size) == size); \
    } while (0);
//------------------------------------------------------------------------------

#endif // __ASSEMBLY__
