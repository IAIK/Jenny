#pragma once
#include "sf.h"
#include "pk_debug.h"

#define ECALL_ROOT_DOMAIN_INIT_ID 0

/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>


#define NUM_CORES sysconf(_SC_NPROCESSORS_ONLN)

bool     PK_CODE _pk_domain_can_access_memory_syscall(int did, const void * addr, size_t len, bool write_access);
int      PK_CODE _pk_domain_can_access_string_syscall(int did, const void * addr, bool write_access);

//------------------------------------------------------------------------------
// Initialization
//------------------------------------------------------------------------------

int _sf_mechanism_ptrace(sf_tracee_function *start);
int _sf_mechanism_ptrace_seccomp(sf_tracee_function *start);
int _sf_mechanism_ptrace_delegate(sf_tracee_function *start);
int _sf_mechanism_seccomp_user(sf_tracee_function *start);
int _sf_mechanism_seccomp(sf_tracee_function *start);

int _sf_mechanism_ptrace_ctor();
int _sf_mechanism_ptrace_ctor_asm();
int _sf_mechanism_ptrace_seccomp_ctor();
int _sf_mechanism_ptrace_seccomp_ctor_asm();
int _sf_mechanism_ptrace_delegate_ctor();
int _sf_mechanism_ptrace_delegate_ctor_asm();
int _sf_mechanism_seccomp_user_ctor();
int _sf_mechanism_seccomp_ctor();

//------------------------------------------------------------------------------
// Internal (API) functions
//------------------------------------------------------------------------------

int  PK_CODE _sf_filters_init(int mechanism, int filter);
ssize_t _sf_write_results(int fd, const void *buf, size_t count);
void PK_CODE _sf_init_base_filters_strace_categorization(void);
//void PK_CODE _sf_localstorage_filters_init(int did);

//------------------------------------------------------------------------------
// (Protected) Sysfilter table
//------------------------------------------------------------------------------

// filter entry for domains
typedef struct {
    filter_t filter;                        // SYSCALL_ALLOWED, SYSCALL_DENIED, or pointer to filtering function taking a trace_info_t struct
    int filter_did;                         // target did, in which the syscall filter should be executed
    arg_copy_t arg_copy[SYSCALL_ARG_COUNT]; // how arguments should be copied
    int flags;
} filter_compact_t;

// manual filters for syscalls, that cannot be categorized by strace
typedef struct {
    int sysno;
    void* filter;
    arg_copy_t arg_copy[SYSCALL_ARG_COUNT];
} sys_manual_t;


//------------------------------------------------------------------------------
// Inline functions
//------------------------------------------------------------------------------

FORCE_INLINE int sf_arg_copy(trace_info_t *ti, int position, size_t size)
{
    assert_ifdebug(ti->mem != NULL);
    void *arg = (void *)ti->args[position];
    if (arg == NULL || !_pk_domain_can_access_memory_syscall(ti->did, arg, size, false)) {
        WARNING("argument at [%p, %p] not accessible by domain", arg, (void *)((uintptr_t)arg + size));
        errno = EFAULT;
        return -1;
    }

    size_t remaining = ARGS_MEM_SIZE - ti->mem_offset;
    if (size > remaining) {
        ERROR_FAIL("not enough memory for syscall argument, %zu", size);
    }

    char *dst = (char *)ti->mem + ti->mem_offset;

    ti->orig_args[position] = (long)arg;
    ti->args[position] = (long)dst;
    pk_memcpy(dst, arg, size);
    ti->mem_offset += size;
    return 0;
}
//------------------------------------------------------------------------------

FORCE_INLINE int sf_arg_string_copy(trace_info_t *ti, int position)
{
    assert_ifdebug(ti->mem != NULL);
    void *arg = (void *)ti->args[position];
    if (arg == NULL) {
        WARNING("argument %d is NULL pointer", position);
        errno = EFAULT;
        return -1;
    }

    size_t max_size = (size_t)_pk_domain_can_access_string_syscall(ti->did, arg, false);
    if (max_size <= 0) {
        WARNING("string argument %d at [%p] not accessible by domain", position, arg);
        errno = EFAULT;
        return -1;
    }
    size_t size = strnlen(arg, max_size) + 1;
    size_t remaining = ARGS_MEM_SIZE - ti->mem_offset;
    if (size > remaining) {
        errno = ENOMEM;
        ERROR_FAIL("not enough memory for syscall argument, %zu", size);
    }

    char *dst = (char *)ti->mem + ti->mem_offset;

    ti->orig_args[position] = (long)arg;
    ti->args[position] = (long)dst;
    pk_memcpy(dst, arg, size);
    ti->mem_offset += size;
    return 0;
}
//------------------------------------------------------------------------------

FORCE_INLINE int sf_arg_alloc(trace_info_t *ti, int position, size_t size)
{
    char *dst = sf_arg_alloc_native(ti, size);
    ti->orig_args[position] = ti->args[position];
    ti->args[position] = (long)dst;
    ti->mem_offset += size;
    return 0;
}
//------------------------------------------------------------------------------

FORCE_INLINE int sf_arg_restore(trace_info_t *ti, int position, size_t size)
{
    assert_ifdebug(ti->mem != NULL);
    assert_ifdebug((uintptr_t)ti->args[position] + size < (uintptr_t)ti->mem + ARGS_MEM_SIZE);

    void *src = (void *)ti->args[position];
    void *dst = (void *)ti->orig_args[position];
    if (dst == NULL || !_pk_domain_can_access_memory_syscall(ti->did, dst, size, true)) {
        WARNING("argument %d at [%p, %p] not accessible by domain", position, dst, (void *)((uintptr_t)dst + size));
        errno = EFAULT;
        return -1;
    }

    pk_memcpy(dst, src, size);
    return 0;
}
//------------------------------------------------------------------------------

// this is executed in monitor before each filtered syscall
// monitor lock is already acquired
FORCE_INLINE int sf_arg_copy_syscall_enter(trace_info_t *ti, arg_copy_t *arg_copy)
{
    for (int pos = 0; pos < SYSCALL_ARG_COUNT; pos++) {

        // for type == *ARGLEN this is a reference to a "size" field in the arguments
        uint8_t length = arg_copy[pos].length;
        switch (arg_copy[pos].type) {
            case ARG_TYPE_NONE:
                // do nothing
            break;
            case ARG_TYPE_COPY:
                DEBUG_SF("copying arg %d with length %d", pos, length);
                if (sf_arg_copy(ti, pos, length) == -1) return -1;
            break;
            case ARG_TYPE_COPY_ARGLEN:
                DEBUG_SF("copying arg %d with length %ld", pos, ti->args[length]);
                if (sf_arg_copy(ti, pos, ti->args[length]) == -1) return -1;
            break;
            case ARG_TYPE_STR_COPY:
                DEBUG_SF("copying string arg %d", pos);
                if (sf_arg_string_copy(ti, pos) == -1) return -1;
            break;
            case ARG_TYPE_ALLOC_RESTORE:
                DEBUG_SF("allocating arg %d with length %d", pos, length);
                if (sf_arg_alloc(ti, pos, length) == -1) return -1;
            break;
            case ARG_TYPE_ALLOC_RESTORE_ARGLEN:
                DEBUG_SF("allocating arg %d with length %ld", pos, ti->args[length]);
                if (sf_arg_alloc(ti, pos, ti->args[length]) == -1) return -1;
            break;
            case ARG_TYPE_CHECK:
                DEBUG_SF("checking arg %d with length %d", pos, length);
                if (!_pk_domain_can_access_memory_syscall(ti->did, (void *)ti->args[pos], length, true)) {
                    errno = EFAULT;
                    return -1;
                }
            break;
            case ARG_TYPE_CHECK_ARGLEN:
                DEBUG_SF("checking arg %d with length %ld", pos, ti->args[length]);
                if (!_pk_domain_can_access_memory_syscall(ti->did, (void *)ti->args[pos], ti->args[length], true)) {
                    errno = EFAULT;
                    return -1;
                }
            break;
            default:
                ERROR_FAIL("syscall argument type not recognized");
        }
    }
    return 0;
}
//------------------------------------------------------------------------------

FORCE_INLINE int sf_arg_copy_syscall_exit(trace_info_t *ti, arg_copy_t *arg_copy)
{
    for (int pos = 0; pos < SYSCALL_ARG_COUNT; pos++) {

        // for type == *ARGLEN this is a reference to a "size" field in the arguments
        uint8_t length = arg_copy[pos].length;
        switch (arg_copy[pos].type) {
            case ARG_TYPE_NONE:
            case ARG_TYPE_COPY:
            case ARG_TYPE_COPY_ARGLEN:
            case ARG_TYPE_STR_COPY:
            case ARG_TYPE_CHECK:
            case ARG_TYPE_CHECK_ARGLEN:
                // do nothing
            break;
            case ARG_TYPE_ALLOC_RESTORE:
                DEBUG_SF("restoring arg %d with length %d", pos, length);
                if (sf_arg_restore(ti, pos, length) == -1) return -1;
            break;
            case ARG_TYPE_ALLOC_RESTORE_ARGLEN:
                DEBUG_SF("restoring arg %d with length %ld", pos, ti->args[length]);
                if (sf_arg_restore(ti, pos, ti->args[length]) == -1) return -1;
            break;
            default:
                ERROR_FAIL("syscall argument type not recognized");
        }
    }
    return 0;
}
//------------------------------------------------------------------------------

#endif // __ASSEMBLY__
