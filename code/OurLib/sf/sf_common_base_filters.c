#include "common_filters.h"

/**
 * This file contains monitor filters for self protection
 */

typedef long (*syscall_to_api_t)(int, long, long, long, long, long, long);

#define WRAPPER(name) \
void PK_CODE wrapper##name(trace_info_t *ti) { \
    syscall_to_api_t sptr = (syscall_to_api_t)name; \
    long ret = sptr(ti->did, ti->args[0], ti->args[1], ti->args[2],  \
                            ti->args[3], ti->args[4], ti->args[5]); \
    if (ret == -1) { \
        SYSFILTER_RETURN(ti, -errno); \
    } else { \
        SYSFILTER_RETURN(ti, ret); \
    } \
}
//------------------------------------------------------------------------------

#define SF_TABLE_SET_FILTER_DIRECT(sysdef, sysfilter) do { \
        int sys = (int)sysdef; \
        if (sys != SYSNO_UNDEFINED) { \
            assert(sys >= 0 && sys < NUM_MONITOR_FILTERS); \
            sf_table[sys].filter = sysfilter; \
        } \
    } while(0)
//------------------------------------------------------------------------------

// do not deny syscall in list directly, but in filter
// (for ptrace seccomp and seccomp user)
void PK_CODE _sf_deny_filter(trace_info_t *ti) {
    DEBUG_FILTER();
    SYSFILTER_RETURN(ti, -EPERM);
}
//------------------------------------------------------------------------------

void _sf_sys_fork(trace_info_t *ti) {
    if (sf_data.sf_mechanism_current == SF_PTRACE || 
        sf_data.sf_mechanism_current == SF_PTRACE_SECCOMP)
    {
        PREPEND_TO_DEBUG_BUFFER("Error. Our ptrace implementation does not yet work with fork."); //because it assumes we are in the same address space and accesses the tracee data directly
        SYSFILTER_RETURN(ti, -EPERM);
    }
}
//we filter clone to distinguish pthreads and forks.
void PK_CODE _sf_sys_clone(trace_info_t *ti) {
    DEBUG_FILTER();

    assert(ti->syscall_nr != SYS_clone3);

    int flags = ti->args[2];

    if(!(flags & CLONE_VM)) { // not in the same address space
        if (sf_data.sf_mechanism_current == SF_PTRACE || 
            sf_data.sf_mechanism_current == SF_PTRACE_SECCOMP)
        {
            PREPEND_TO_DEBUG_BUFFER(COLOR_RED "Error. Our ptrace implementation does not yet work with fork."); //because it assumes we are in the same address space and accesses the tracee data directly
            SYSFILTER_RETURN(ti, -EPERM);
        }
    }
}
//------------------------------------------------------------------------------

void PK_CODE _sf_sys_test_return_value(trace_info_t *ti) {
    DEBUG_FILTER();
    assert_ifdebug(ti->syscall_nr == SYS_test_return_value);
    SYSFILTER_RETURN(ti, 0xC0FEC0FE);
}
//------------------------------------------------------------------------------

void PK_CODE _sf_sys_test_arg_copying(trace_info_t *ti) {
    DEBUG_FILTER();
    assert_ifdebug(ti->syscall_nr == SYS_test_arg_copying);
    char memory[10];

    _pk_acquire_lock();
    assert(_pk_domain_can_access_memory_syscall(ti->did, memory, sizeof(memory), 0) == false);
    assert(_pk_domain_can_access_memory_syscall(ti->did, &pk_data, 10, 0) == true);
    assert(_pk_domain_can_access_memory_syscall(ti->did, &pk_data, 10, 1) == false);
    _pk_release_lock();
    SYSFILTER_RETURN(ti, 0xCAFE);
}
//------------------------------------------------------------------------------
static void PK_CODE _sf_sys_close(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (IS_SYSCALL_ENTER(ti)) {
        int fd = (int)ti->args[0];
        if(! _fd_accessible_by_domain(ti->did, fd)){
            WARNING("%s: FD %d not accessible by domain %d", sysno_to_str(ti->syscall_nr), fd, ti->did);
            SYSFILTER_RETURN(ti, -EBADF);
        }
        //PREPEND_TO_DEBUG_BUFFER("sf_data.fd_domain_mapping[%d] = %d\n", fd, sf_data.fd_domain_mapping[fd]);
        //NOTE: we are not using SYSFILTER_CHECK_FD since there are other syscalls that can create a FD, which we have not traced
    } else {
        int ret = ti->return_value;
        if(0 == ret) {
            int fd = (int)ti->args[0];
            assert(fd >= 0 && fd < NUM_FDS);
            sf_data.fd_domain_mapping[fd] = FD_DOMAIN_NONE_OR_CLOSED;
        }
    }
}
//------------------------------------------------------------------------------

// Generate wrapper functions
WRAPPER(_pk_mmap2)
WRAPPER(_pk_mprotect2)
WRAPPER(_pk_mremap2)
WRAPPER(_pk_munmap2)
WRAPPER(_pk_madvise2)
WRAPPER(_pk_pkey_alloc2)
WRAPPER(_pk_pkey_free2)
WRAPPER(_pk_pkey_mprotect2)
WRAPPER(_pk_sigaction_krnl2)
WRAPPER(_pk_signal2)
//------------------------------------------------------------------------------


void PK_CODE wrapper_pk_sigaltstack2(trace_info_t *ti){
    #ifndef RELEASE
    WARNING("ignoring sigaltstack because we have our own.");
    #endif
    SYSFILTER_RETURN(ti, 0);
}
//------------------------------------------------------------------------------

#define SYSCALL_DENIED_EXCEPT_MONITOR _sf_deny_filter

#define FILTER_SET_ROBUST_LIST    _sf_empty_filter,           {{ARG_TYPE_CHECK_ARGLEN, 1}}

static sys_manual_t PK_DATA syscalls_manual[] = {
    { SYS_getuid,                _sf_empty_filter,          },

    { SYS_brk,                   SYSCALL_ALLOWED,           },
    { SYS_sbrk,                  SYSCALL_ALLOWED,           },
    { SYS_mmap,                  wrapper_pk_mmap2,          },
    { SYS_mmap2,                 wrapper_pk_mmap2,          },
    { SYS_mprotect,              wrapper_pk_mprotect2,      },
    { SYS_mremap,                wrapper_pk_mremap2,        },
    { SYS_munmap,                wrapper_pk_munmap2,        },
    { SYS_madvise,               wrapper_pk_madvise2,       },
    { SYS_pkey_alloc,            wrapper_pk_pkey_alloc2,    },
    { SYS_pkey_free,             wrapper_pk_pkey_free2,     },
    { SYS_pkey_mprotect,         wrapper_pk_pkey_mprotect2, },

#ifdef UNSAFE_SIGNALS
    { SYS_sigaction,             SYSCALL_ALLOWED,           },
    { SYS_rt_sigaction,          SYSCALL_ALLOWED,           },
    { SYS_rt_sigreturn,          SYSCALL_ALLOWED,           },
    { SYS_signal,                SYSCALL_ALLOWED,           },
    { SYS_sigaltstack,           SYSCALL_ALLOWED,           },
    { SYS_rt_sigreturn,          SYSCALL_ALLOWED,           },
#else
    { SYS_sigaction,             wrapper_pk_sigaction_krnl2,},
    { SYS_rt_sigaction,          wrapper_pk_sigaction_krnl2,},
    { SYS_rt_sigreturn,          SYSCALL_ALLOWED,           },
    { SYS_signal,                wrapper_pk_signal2,        },
    { SYS_sigaltstack,           wrapper_pk_sigaltstack2,   },
    { SYS_rt_sigreturn,          SYSCALL_DENIED_EXCEPT_MONITOR,   },
#endif
    { SYS_sched_yield,           SYSCALL_ALLOWED            },
    { SYS_nanosleep,             SYSCALL_ALLOWED            },
    { SYS_getitimer,             SYSCALL_ALLOWED            },
    { SYS_alarm,                 SYSCALL_ALLOWED            },
    { SYS_setitimer,             SYSCALL_ALLOWED            },
    { SYS_uname,                 SYSCALL_ALLOWED            },
    { SYS_umask,                 SYSCALL_DENIED             },
    { SYS_getrlimit,             SYSCALL_ALLOWED            },
    { SYS_getrusage,             SYSCALL_ALLOWED            },
    { SYS_sysinfo,               SYSCALL_ALLOWED            },
    { SYS_times,                 SYSCALL_ALLOWED            },
    { SYS_ptrace,                SYSCALL_DENIED             },
    { SYS_syslog,                SYSCALL_ALLOWED            },
    { SYS_setpgid,               SYSCALL_DENIED             },
    { SYS_setsid,                SYSCALL_DENIED             },
    { SYS_getpgid,               SYSCALL_ALLOWED            },
    { SYS_getsid,                SYSCALL_ALLOWED            },
    { SYS_personality,           SYSCALL_DENIED             },
    { SYS_sysfs,                 SYSCALL_ALLOWED            },
    { SYS_getpriority,           SYSCALL_ALLOWED            },
    { SYS_setpriority,           SYSCALL_ALLOWED            },
    { SYS_sched_setparam,        SYSCALL_ALLOWED            },
    { SYS_sched_getparam,        SYSCALL_ALLOWED            },
    { SYS_sched_setscheduler,    SYSCALL_ALLOWED            },
    { SYS_sched_getscheduler,    SYSCALL_ALLOWED            },
    { SYS_sched_get_priority_max,SYSCALL_ALLOWED            },
    { SYS_sched_get_priority_min,SYSCALL_ALLOWED            },
    { SYS_sched_rr_get_interval, SYSCALL_ALLOWED            },
    { SYS_vhangup,               SYSCALL_ALLOWED            },
    { SYS_modify_ldt,            SYSCALL_DENIED             },
    { SYS__sysctl,               SYSCALL_DENIED             },
    { SYS_prctl,                 SYSCALL_DENIED             },
    { SYS_arch_prctl,            SYSCALL_DENIED             },
    { SYS_setrlimit,             SYSCALL_DENIED             },
    { SYS_sync,                  SYSCALL_ALLOWED            },
    { SYS_reboot,                SYSCALL_DENIED             },
    { SYS_sethostname,           SYSCALL_DENIED             },
    { SYS_setdomainname,         SYSCALL_DENIED             },
    { SYS_iopl,                  SYSCALL_ALLOWED            },
    { SYS_ioperm,                SYSCALL_ALLOWED            },
    { SYS_create_module,         SYSCALL_DENIED             },
    { SYS_init_module,           SYSCALL_DENIED             },
    { SYS_finit_module,          SYSCALL_DENIED             },
    { SYS_delete_module,         SYSCALL_DENIED             },
    { SYS_get_kernel_syms,       SYSCALL_DENIED             },
    { SYS_query_module,          SYSCALL_DENIED             },
    { SYS_nfsservctl,            SYSCALL_DENIED             },
    { SYS_afs_syscall,           SYSCALL_DENIED             },
    { SYS_tuxcall,               SYSCALL_DENIED             },
    { SYS_security,              SYSCALL_DENIED             },
    { SYS_futex,                 SYSCALL_ALLOWED            },
    { SYS_sched_setaffinity,     SYSCALL_ALLOWED            },
    { SYS_sched_getaffinity,     SYSCALL_ALLOWED            },
    { SYS_set_thread_area,       SYSCALL_DENIED             },
    { SYS_io_getevents,          SYSCALL_ALLOWED            },
    { SYS_io_submit,             SYSCALL_ALLOWED            },
    { SYS_io_cancel,             SYSCALL_ALLOWED            },
    { SYS_get_thread_area,       SYSCALL_ALLOWED            },
    { SYS_lookup_dcookie,        SYSCALL_ALLOWED            },
    { SYS_epoll_ctl_old,         SYSCALL_ALLOWED            },
    { SYS_epoll_wait_old,        SYSCALL_ALLOWED            },
    { SYS_set_tid_address,       SYSCALL_DENIED             },
    { SYS_restart_syscall,       SYSCALL_ALLOWED            },
    { SYS_timer_create,          SYSCALL_ALLOWED            },
    { SYS_timer_settime,         SYSCALL_ALLOWED            },
    { SYS_timer_gettime,         SYSCALL_ALLOWED            },
    { SYS_timer_getoverrun,      SYSCALL_ALLOWED            },
    { SYS_timer_delete,          SYSCALL_ALLOWED            },
    { SYS_clock_nanosleep,       SYSCALL_ALLOWED            },
    { SYS_vserver,               SYSCALL_DENIED             },
    { SYS_mq_unlink,             SYSCALL_ALLOWED            },
    { SYS_kexec_load,            SYSCALL_DENIED             },
    { SYS_kexec_file_load,       SYSCALL_DENIED             },
    { SYS_bpf,                   SYSCALL_DENIED             },
    { SYS_userfaultfd,           SYSCALL_DENIED             },
    { SYS_add_key,               SYSCALL_DENIED             },
    { SYS_request_key,           SYSCALL_DENIED             },
    { SYS_keyctl,                SYSCALL_DENIED             },
    { SYS_ioprio_set,            SYSCALL_ALLOWED            },
    { SYS_ioprio_get,            SYSCALL_ALLOWED            },
    { SYS_unshare,               SYSCALL_DENIED             },
    { SYS_set_robust_list,       FILTER_SET_ROBUST_LIST     },
    { SYS_get_robust_list,       SYSCALL_ALLOWED            },
    { SYS_prlimit64,             SYSCALL_ALLOWED            },
    { SYS_getcpu,                SYSCALL_ALLOWED            },
    { SYS_process_vm_readv,      SYSCALL_DENIED             },
    { SYS_process_vm_writev,     SYSCALL_DENIED             },
    { SYS_kcmp,                  SYSCALL_ALLOWED            },
    { SYS_sched_setattr,         SYSCALL_ALLOWED            },
    { SYS_sched_getattr,         SYSCALL_ALLOWED            },
    { SYS_seccomp,               SYSCALL_DENIED             },
    { SYS_getrandom,             SYSCALL_ALLOWED            },
    { SYS_membarrier,            SYSCALL_ALLOWED            },
    { SYS_io_pgetevents,         SYSCALL_ALLOWED            },
    { SYS_rseq,                  SYSCALL_DENIED             },
    { SYS_mount,                 SYSCALL_DENIED             },
    { SYS_chroot,                SYSCALL_DENIED             },
    { SYS_umount2,               SYSCALL_DENIED             },
    { SYS_pivot_root,            SYSCALL_DENIED             },
#ifdef __x86_64__
    { SYS_open_tree,             SYSCALL_DENIED             },
    { SYS_move_mount,            SYSCALL_DENIED             },
    { SYS_fsopen,                SYSCALL_DENIED             },
    { SYS_fsconfig,              SYSCALL_DENIED             },
    { SYS_fsmount,               SYSCALL_DENIED             },
    { SYS_fspick,                SYSCALL_DENIED             },
#endif
    { SYS_exit,                  SYSCALL_ALLOWED            },
    { SYS_exit_group,            SYSCALL_ALLOWED            },
    { SYS_kill,                  SYSCALL_ALLOWED            },
    { SYS_tkill,                 SYSCALL_ALLOWED            },
    { SYS_tgkill,                SYSCALL_ALLOWED            },

    { SYS_fork,                  _sf_sys_fork               },
    { SYS_vfork,                 _sf_sys_fork               },
    { SYS_clone,                 _sf_sys_clone              },
    { SYS_clone2,                _sf_sys_clone              },
    { SYS_clone3,                _sf_sys_clone              },

    { SYS_getcwd,                SYSCALL_ALLOWED            },
    { SYS_waitpid,               SYSCALL_ALLOWED            }, 
    { SYS_wait4,                 SYSCALL_ALLOWED            }, 
    { SYS_waittid,               SYSCALL_ALLOWED            }, 
    { SYS_select,                SYSCALL_ALLOWED            },
    { SYS_epoll_create,          SYSCALL_ALLOWED            },
    { SYS_epoll_create1,         SYSCALL_ALLOWED            },
    { SYS_epoll_ctl,             SYSCALL_ALLOWED            },
    { SYS_epoll_wait,            SYSCALL_ALLOWED            },
    { SYS_epoll_pwait,           SYSCALL_ALLOWED            },
    { SYS_timerfd_create,        SYSCALL_ALLOWED            },
    { SYS_eventfd,               SYSCALL_ALLOWED            },
    { SYS_eventfd2,              SYSCALL_ALLOWED            },
    { SYS_memfd_create,          SYSCALL_ALLOWED            },
    { SYS_pidfd_getfd,           SYSCALL_ALLOWED            },
    { SYS_pidfd_open,            SYSCALL_ALLOWED            },
    { SYS_poll,                  SYSCALL_ALLOWED            },
    { SYS_ppoll,                 SYSCALL_ALLOWED            },
    { SYS_mq_notify,             SYSCALL_ALLOWED            },
    { SYS_mq_open,               SYSCALL_ALLOWED            },
    { SYS_mq_timedreceive,       SYSCALL_ALLOWED            },
    { SYS_mq_timedsend,          SYSCALL_ALLOWED            },
    { SYS_mq_getsetattr,         SYSCALL_ALLOWED            },
    { SYS_inotify_init,          SYSCALL_ALLOWED            },
    { SYS_inotify_init1,         SYSCALL_ALLOWED            },
    { SYS_inotify_rm_watch,      SYSCALL_ALLOWED            },
    { SYS_pselect6,              SYSCALL_ALLOWED            },
    { SYS_perf_event_open,       SYSCALL_ALLOWED            },
    { SYS_fanotify_init,         SYSCALL_ALLOWED            },
    { SYS_open_by_handle_at,     SYSCALL_ALLOWED            },
    { SYS_io_uring_enter,        SYSCALL_ALLOWED            },
    { SYS_io_uring_register,     SYSCALL_ALLOWED            },
    { SYS_io_uring_setup,        SYSCALL_ALLOWED            },
    { SYS_ioctl,                 SYSCALL_ALLOWED            },
    { SYS_access,                SYSCALL_ALLOWED            },

    //these are handled by _sf_init_base_filters_strace_categorization
    //{ SYS_rt_sigqueueinfo,       SYSCALL_DENIED             },
    //{ SYS_rt_tgsigqueueinfo,     SYSCALL_DENIED             },
    //{ SYS_execve,                SYSCALL_DENIED             },
    //{ SYS_execveat,              SYSCALL_DENIED             },
    //{ SYS_fork,                  SYSCALL_DENIED             },
    //{ SYS_vfork,                 SYSCALL_DENIED             },
    //{ SYS_shmat,                 SYSCALL_DENIED             },
    //{ SYS_shmdt,                 SYSCALL_DENIED             },
    //{ SYS_remap_file_pages,      SYSCALL_DENIED             },
    //{ SYS_setuid,                SYSCALL_DENIED             },
    //{ SYS_setgid,                SYSCALL_DENIED             },
    //{ SYS_setreuid,              SYSCALL_DENIED             },
    //{ SYS_setregid,              SYSCALL_DENIED             },
    //{ SYS_setgroups,             SYSCALL_DENIED             },
    //{ SYS_setresuid,             SYSCALL_DENIED             },
    //{ SYS_setresgid,             SYSCALL_DENIED             },
    //{ SYS_setfsuid,              SYSCALL_DENIED             },
    //{ SYS_setfsgid,              SYSCALL_DENIED             },
    //{ SYS_capset,                SYSCALL_DENIED             },

    // testing syscalls
    { SYS_test_arg_copying,      _sf_sys_test_arg_copying   },
    { SYS_test_return_value,     _sf_sys_test_return_value  },
};
//------------------------------------------------------------------------------

void PK_CODE _sf_init_base_filters_strace_categorization() {

    DEBUG_SF("initializing base filters");
    // Allow syscalls based on categories
    // Some of them will be denied later on
    for (long sysno = 0; sysno < NUM_MONITOR_FILTERS; sysno++) {
        sysent_t * sysent = &sf_table[sysno];

        if (sysent->sys_flags & TRACE_DESC || sysent->sys_flags & TRACE_FILE) {
            DEBUG_SF("Selfprotect: Allowing FD syscall %3zu '%s'", sysno, sysno_to_str(sysno));
            sysent->filter = SYSCALL_ALLOWED;
        } else if (sysent->sys_flags & (TRACE_IPC)) {
            DEBUG_SF("Selfprotect: Allowing IPC syscall %3zu '%s'", sysno, sysno_to_str(sysno));
            sysent->filter = SYSCALL_ALLOWED;
        } else if (sysent->sys_flags & (TRACE_SIGNAL)) {
            DEBUG_SF("Selfprotect: Allowing SIGNAL syscall %3zu '%s'", sysno, sysno_to_str(sysno));
            sysent->filter = SYSCALL_ALLOWED;
        } else if (sysent->sys_flags & (TRACE_NETWORK)) {
            DEBUG_SF("Selfprotect: Allowing NETWORK syscall %3zu '%s'", sysno, sysno_to_str(sysno));
            sysent->filter = SYSCALL_ALLOWED;
        } else if (sysent->sys_flags & (TRACE_STAT | TRACE_LSTAT | TRACE_FSTAT |
                  TRACE_STAT_LIKE | TRACE_STATFS | TRACE_FSTATFS | TRACE_STATFS_LIKE)) {
            DEBUG_SF("Selfprotect: Allowing STAT syscall %3zu '%s'", sysno, sysno_to_str(sysno));
            sysent->filter = SYSCALL_ALLOWED;
        } else if (sysent->sys_flags & TRACE_MEMORY && !(sysent->sys_flags & MEMORY_MAPPING_CHANGE)) {
            DEBUG_SF("Selfprotect: Allowing uncritical MEMORY syscall %3zu '%s'", sysno, sysno_to_str(sysno));
            sysent->filter = SYSCALL_ALLOWED;
        } else if (sysent->sys_flags & TRACE_CREDS && sysent->sys_flags & TRACE_PURE) {
            DEBUG_SF("Selfprotect: Allowing CREDENTIAL getter syscall %3zu '%s'", sysno, sysno_to_str(sysno));
            sysent->filter = SYSCALL_ALLOWED;
        } else if (sysent->sys_flags & (TRACE_PURE | TRACE_CLOCK)) {
            DEBUG_SF("Selfprotect: Allowing uncritical PURE/CLOCK syscall %3zu '%s'", sysno, sysno_to_str(sysno));
            sysent->filter = SYSCALL_ALLOWED;
        }
    }

    // Deny dangerous syscalls based on categories
    // Some of them will be emulated later on
    for (long sysno = 0; sysno < NUM_MONITOR_FILTERS; sysno++) {
        sysent_t * sysent = &sf_table[sysno];
        if (sysent->sys_flags & TRACE_PROCESS) {
            DEBUG_SF("Selfprotect: Denying PROCESS syscall %3ld '%s'", sysno, sysno_to_str(sysno));
            sysent->filter = SYSCALL_DENIED;
        } else if (sysent->sys_flags & TRACE_MEMORY && sysent->sys_flags & MEMORY_MAPPING_CHANGE) {
            DEBUG_SF("Selfprotect: Denying MEMORY MAPPING syscall %3ld '%s'", sysno, sysno_to_str(sysno));
            sysent->filter = SYSCALL_DENIED;
        } else if (sysent->sys_flags & TRACE_CREDS && !(sysent->sys_flags & TRACE_PURE)) {
            DEBUG_SF("Selfprotect: Denying CREDENTIAL setter syscall %3ld '%s'", sysno, sysno_to_str(sysno));
            sysent->filter = SYSCALL_DENIED;
        }
    }
}
//------------------------------------------------------------------------------

void PK_CODE _sf_init_sf_data(int mechanism, int filter)
{
    for (size_t i = 0; i < NUM_FDS; i++) {
        sf_data.fd_domain_mapping[i] = FD_DOMAIN_NONE_OR_CLOSED;
    }

    sf_data.fd_domain_mapping[STDIN_FILENO]  = FD_DOMAIN_ANY;
    sf_data.fd_domain_mapping[STDOUT_FILENO] = FD_DOMAIN_ANY;
    sf_data.fd_domain_mapping[STDERR_FILENO] = FD_DOMAIN_ANY;
}
//------------------------------------------------------------------------------

int PK_CODE _sf_filters_init(int mechanism, int filter)
{
    int ret = 0;
    _pk_acquire_lock();

    if (sf_data.sf_filters_initialized) {
        ERROR("SF filters already initialized");
        errno = EACCES;
        ret = -1;
        goto cleanup;
    }

    // name custom syscalls
    sf_table[SYS_test_return_value].sys_name = "test_return_value";
    sf_table[SYS_test_arg_copying].sys_name = "test_arg_copying";

    if (filter == SF_NONE || filter == SF_JUST_DOMAIN) {
        // Set all syscalls to allow
        for (long sysno = 0; sysno < NUM_MONITOR_FILTERS; sysno++) {
            sysent_t * sysent = &sf_table[sysno];
            sysent->filter = SYSCALL_ALLOWED;
        }

        //for benchmarking: register a single filter
        //using unused syscall number
        sf_table[400].filter = SYSCALL_DENIED;

    } else {
        // Initialize base filters
        _sf_init_base_filters_strace_categorization();
        // always use prctl as part of our self-protection
        _sf_base_filters_prctl_init();

        // for nested benchmark
        //if (sf_data.sf_filter_current == SF_EXTENDED_DOMAIN) {
        //    sf_table[SYS_getpid].filter = _sf_empty_filter;
        //}
        sf_table[SYS_getpid].filter = _sf_empty_filter; // for benchmarking

        // Initialize additional self-protection filters
        // Make sure they do not allow already denied filters!
        if (filter == SF_SELF_DONKY) {
            //nothing to do
        } else if (filter == SF_SELF_MPK
         || filter == SF_EXTENDED_MONITOR 
         || filter == SF_EXTENDED_DOMAIN
        ){
            //NOTE: localstorage is (now) a superset of self-mpk
            _pk_set_binary_scanning_unlocked(1);
        }

        //deprecated:
        else if (filter == SF_SELF) {
            _sf_base_filters_sanitization_init();
        } else if (filter == SF_SELF_OPEN) {
            _sf_base_filters_open_init();
        }

        // apply custom base filters at end to override already registered filters
        // NOTE: this must happen after _sf_init_base_filters_strace_categorization
        _apply_custom_filters(syscalls_manual, sizeof(syscalls_manual) / sizeof(sys_manual_t));

        //----------------------------------------------------------------------
        if (sf_data.sf_mechanism_current == SF_PTRACE || 
            sf_data.sf_mechanism_current == SF_PTRACE_SECCOMP || 
            sf_data.sf_mechanism_current == SF_SECCOMP_USER)
        {
            SF_TABLE_SET_FILTER_DIRECT(SYS_mmap, SYSCALL_ALLOWED);
            SF_TABLE_SET_FILTER_DIRECT(SYS_mremap, SYSCALL_ALLOWED);
            SF_TABLE_SET_FILTER_DIRECT(SYS_munmap, SYSCALL_ALLOWED);
            SF_TABLE_SET_FILTER_DIRECT(SYS_mprotect, SYSCALL_ALLOWED);
            SF_TABLE_SET_FILTER_DIRECT(SYS_pkey_alloc, SYSCALL_ALLOWED);
            SF_TABLE_SET_FILTER_DIRECT(SYS_pkey_free, SYSCALL_ALLOWED);
            SF_TABLE_SET_FILTER_DIRECT(SYS_pkey_mprotect, SYSCALL_ALLOWED);
            SF_TABLE_SET_FILTER_DIRECT(SYS_madvise, SYSCALL_ALLOWED);
            SF_TABLE_SET_FILTER_DIRECT(SYS_sigaction, SYSCALL_ALLOWED);
            SF_TABLE_SET_FILTER_DIRECT(SYS_rt_sigaction, SYSCALL_ALLOWED);
            SF_TABLE_SET_FILTER_DIRECT(SYS_signal, SYSCALL_ALLOWED);
        }
        if (sf_data.sf_mechanism_current == SF_SECCOMP_USER) {
            SF_TABLE_SET_FILTER_DIRECT(SYS_fork, SYSCALL_DENIED);
            SF_TABLE_SET_FILTER_DIRECT(SYS_vfork, SYSCALL_DENIED);
            SF_TABLE_SET_FILTER_DIRECT(SYS_clone, SYSCALL_DENIED);
            SF_TABLE_SET_FILTER_DIRECT(SYS_clone2, SYSCALL_DENIED);
            SF_TABLE_SET_FILTER_DIRECT(SYS_clone3, SYSCALL_DENIED);
        }
    }
    //--------------------------------------------------------------------------
    for (long sysno = 0; sysno < NUM_MONITOR_FILTERS; sysno++) {
        sysent_t * sysent = &sf_table[sysno];
        if (sysent->filter == SYSCALL_UNSPECIFIED) {
#ifndef RELEASE
            // Print warnings on unprocessed syscalls
            WARNING("Selfprotect: unhandled syscall %3ld '%s'", sysno, sysent_to_syscall_str(sysent));
#endif
        } else if (sysent->filter != SYSCALL_ALLOWED) {
            // Register syscalls in sysfilter module
            _pk_sysfilter_module_intercept(sysno);
        }
    }
    //--------------------------------------------------------------------------
    if (mechanism == SF_USERMODE) {
        ENABLE_SYSCALL_DELEGATION();
    }
#ifdef __x86_64__
    else if (mechanism == SF_INDIRECT) {
        _pk_syscall_handler_ptr = &_pk_syscall_handler;
        // Initialize handler in fs such that modded libc can find
        // our handler. The fs-offset is hardcoded in INDIRECT_CALL_OFFSET
        // this only works for current thread. To do it for all threads, 
        // we currently set the INDIRECT_CALL_OFFSET at each monitor exit
        asm volatile(
            "movq %0, %%fs:(%1)\n"
            :
            : "r"(_pk_syscall_handler_ptr), "c"(INDIRECT_CALL_OFFSET));
        }
#endif

    //--------------------------------------------------------------------------
    // initialize other data structures:
    _sf_init_sf_data(mechanism, filter);
    sf_data.sf_filters_initialized = true;

cleanup:
    _pk_release_lock();
    return ret;
}
//------------------------------------------------------------------------------
