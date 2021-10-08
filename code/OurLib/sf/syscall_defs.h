#pragma once
#include <limits.h>

// Choose a large number such that any misuse, e.g., as an index into
// sf_table more likely triggers a SEGFAULT
#define SYSNO_UNDEFINED INT_MIN

#ifndef SYS_FAST_atomic_update
# define SYS_FAST_atomic_update SYSNO_UNDEFINED
#endif

#ifndef SYS_FAST_cmpxchg
# define SYS_FAST_cmpxchg SYSNO_UNDEFINED
#endif

#ifndef SYS_FAST_cmpxchg64
# define SYS_FAST_cmpxchg64 SYSNO_UNDEFINED
#endif

#ifndef SYS__llseek
# define SYS__llseek SYSNO_UNDEFINED
#endif

#ifndef SYS__newselect
# define SYS__newselect SYSNO_UNDEFINED
#endif

#ifndef SYS__sysctl
# define SYS__sysctl SYSNO_UNDEFINED
#endif

#ifndef SYS_accept
# define SYS_accept SYSNO_UNDEFINED
#endif

#ifndef SYS_accept4
# define SYS_accept4 SYSNO_UNDEFINED
#endif

#ifndef SYS_access
# define SYS_access SYSNO_UNDEFINED
#endif

#ifndef SYS_acct
# define SYS_acct SYSNO_UNDEFINED
#endif

#ifndef SYS_acl_get
# define SYS_acl_get SYSNO_UNDEFINED
#endif

#ifndef SYS_acl_set
# define SYS_acl_set SYSNO_UNDEFINED
#endif

#ifndef SYS_add_key
# define SYS_add_key SYSNO_UNDEFINED
#endif

#ifndef SYS_adjtimex
# define SYS_adjtimex SYSNO_UNDEFINED
#endif

#ifndef SYS_afs_syscall
# define SYS_afs_syscall SYSNO_UNDEFINED
#endif

#ifndef SYS_alarm
# define SYS_alarm SYSNO_UNDEFINED
#endif

#ifndef SYS_alloc_hugepages
# define SYS_alloc_hugepages SYSNO_UNDEFINED
#endif

#ifndef SYS_arc_gettls
# define SYS_arc_gettls SYSNO_UNDEFINED
#endif

#ifndef SYS_arc_settls
# define SYS_arc_settls SYSNO_UNDEFINED
#endif

#ifndef SYS_arc_usr_cmpxchg
# define SYS_arc_usr_cmpxchg SYSNO_UNDEFINED
#endif

#ifndef SYS_arch_prctl
# define SYS_arch_prctl SYSNO_UNDEFINED
#endif

#ifndef SYS_arm_fadvise64_64
# define SYS_arm_fadvise64_64 SYSNO_UNDEFINED
#endif

#ifndef SYS_arm_sync_file_range
# define SYS_arm_sync_file_range SYSNO_UNDEFINED
#endif

#ifndef SYS_atomic_barrier
# define SYS_atomic_barrier SYSNO_UNDEFINED
#endif

#ifndef SYS_atomic_cmpxchg_32
# define SYS_atomic_cmpxchg_32 SYSNO_UNDEFINED
#endif

#ifndef SYS_attrctl
# define SYS_attrctl SYSNO_UNDEFINED
#endif

#ifndef SYS_bdflush
# define SYS_bdflush SYSNO_UNDEFINED
#endif

#ifndef SYS_bind
# define SYS_bind SYSNO_UNDEFINED
#endif

#ifndef SYS_bpf
# define SYS_bpf SYSNO_UNDEFINED
#endif

#ifndef SYS_break
# define SYS_break SYSNO_UNDEFINED
#endif

#ifndef SYS_breakpoint
# define SYS_breakpoint SYSNO_UNDEFINED
#endif

#ifndef SYS_brk
# define SYS_brk SYSNO_UNDEFINED
#endif

#ifndef SYS_sbrk
# define SYS_sbrk SYSNO_UNDEFINED
#endif

#ifndef SYS_cachectl
# define SYS_cachectl SYSNO_UNDEFINED
#endif

#ifndef SYS_cacheflush
# define SYS_cacheflush SYSNO_UNDEFINED
#endif

#ifndef SYS_capget
# define SYS_capget SYSNO_UNDEFINED
#endif

#ifndef SYS_capset
# define SYS_capset SYSNO_UNDEFINED
#endif

#ifndef SYS_chdir
# define SYS_chdir SYSNO_UNDEFINED
#endif

#ifndef SYS_chmod
# define SYS_chmod SYSNO_UNDEFINED
#endif

#ifndef SYS_chown
# define SYS_chown SYSNO_UNDEFINED
#endif

#ifndef SYS_chown32
# define SYS_chown32 SYSNO_UNDEFINED
#endif

#ifndef SYS_chroot
# define SYS_chroot SYSNO_UNDEFINED
#endif

#ifndef SYS_clock_adjtime
# define SYS_clock_adjtime SYSNO_UNDEFINED
#endif

#ifndef SYS_clock_adjtime64
# define SYS_clock_adjtime64 SYSNO_UNDEFINED
#endif

#ifndef SYS_clock_getres
# define SYS_clock_getres SYSNO_UNDEFINED
#endif

#ifndef SYS_clock_getres_time64
# define SYS_clock_getres_time64 SYSNO_UNDEFINED
#endif

#ifndef SYS_clock_gettime
# define SYS_clock_gettime SYSNO_UNDEFINED
#endif

#ifndef SYS_clock_gettime64
# define SYS_clock_gettime64 SYSNO_UNDEFINED
#endif

#ifndef SYS_clock_nanosleep
# define SYS_clock_nanosleep SYSNO_UNDEFINED
#endif

#ifndef SYS_clock_nanosleep_time64
# define SYS_clock_nanosleep_time64 SYSNO_UNDEFINED
#endif

#ifndef SYS_clock_settime
# define SYS_clock_settime SYSNO_UNDEFINED
#endif

#ifndef SYS_clock_settime64
# define SYS_clock_settime64 SYSNO_UNDEFINED
#endif

#ifndef SYS_clone
# define SYS_clone SYSNO_UNDEFINED
#endif

#ifndef SYS_clone2
# define SYS_clone2 SYSNO_UNDEFINED
#endif

#ifndef SYS_clone3
# define SYS_clone3 SYSNO_UNDEFINED
#endif

#ifndef SYS_close
# define SYS_close SYSNO_UNDEFINED
#endif

#ifndef SYS_cmpxchg_badaddr
# define SYS_cmpxchg_badaddr SYSNO_UNDEFINED
#endif

#ifndef SYS_connect
# define SYS_connect SYSNO_UNDEFINED
#endif

#ifndef SYS_copy_file_range
# define SYS_copy_file_range SYSNO_UNDEFINED
#endif

#ifndef SYS_creat
# define SYS_creat SYSNO_UNDEFINED
#endif

#ifndef SYS_create_module
# define SYS_create_module SYSNO_UNDEFINED
#endif

#ifndef SYS_delete_module
# define SYS_delete_module SYSNO_UNDEFINED
#endif

#ifndef SYS_dipc
# define SYS_dipc SYSNO_UNDEFINED
#endif

#ifndef SYS_dup
# define SYS_dup SYSNO_UNDEFINED
#endif

#ifndef SYS_dup2
# define SYS_dup2 SYSNO_UNDEFINED
#endif

#ifndef SYS_dup3
# define SYS_dup3 SYSNO_UNDEFINED
#endif

#ifndef SYS_epoll_create
# define SYS_epoll_create SYSNO_UNDEFINED
#endif

#ifndef SYS_epoll_create1
# define SYS_epoll_create1 SYSNO_UNDEFINED
#endif

#ifndef SYS_epoll_ctl
# define SYS_epoll_ctl SYSNO_UNDEFINED
#endif

#ifndef SYS_epoll_ctl_old
# define SYS_epoll_ctl_old SYSNO_UNDEFINED
#endif

#ifndef SYS_epoll_pwait
# define SYS_epoll_pwait SYSNO_UNDEFINED
#endif

#ifndef SYS_epoll_wait
# define SYS_epoll_wait SYSNO_UNDEFINED
#endif

#ifndef SYS_epoll_wait_old
# define SYS_epoll_wait_old SYSNO_UNDEFINED
#endif

#ifndef SYS_eventfd
# define SYS_eventfd SYSNO_UNDEFINED
#endif

#ifndef SYS_eventfd2
# define SYS_eventfd2 SYSNO_UNDEFINED
#endif

#ifndef SYS_exec_with_loader
# define SYS_exec_with_loader SYSNO_UNDEFINED
#endif

#ifndef SYS_execv
# define SYS_execv SYSNO_UNDEFINED
#endif

#ifndef SYS_execve
# define SYS_execve SYSNO_UNDEFINED
#endif

#ifndef SYS_execveat
# define SYS_execveat SYSNO_UNDEFINED
#endif

#ifndef SYS_exit
# define SYS_exit SYSNO_UNDEFINED
#endif

#ifndef SYS_exit_group
# define SYS_exit_group SYSNO_UNDEFINED
#endif

#ifndef SYS_faccessat
# define SYS_faccessat SYSNO_UNDEFINED
#endif

#ifndef SYS_fadvise64
# define SYS_fadvise64 SYSNO_UNDEFINED
#endif

#ifndef SYS_fadvise64_64
# define SYS_fadvise64_64 SYSNO_UNDEFINED
#endif

#ifndef SYS_fallocate
# define SYS_fallocate SYSNO_UNDEFINED
#endif

#ifndef SYS_fanotify_init
# define SYS_fanotify_init SYSNO_UNDEFINED
#endif

#ifndef SYS_fanotify_mark
# define SYS_fanotify_mark SYSNO_UNDEFINED
#endif

#ifndef SYS_fchdir
# define SYS_fchdir SYSNO_UNDEFINED
#endif

#ifndef SYS_fchmod
# define SYS_fchmod SYSNO_UNDEFINED
#endif

#ifndef SYS_fchmodat
# define SYS_fchmodat SYSNO_UNDEFINED
#endif

#ifndef SYS_fchown
# define SYS_fchown SYSNO_UNDEFINED
#endif

#ifndef SYS_fchown32
# define SYS_fchown32 SYSNO_UNDEFINED
#endif

#ifndef SYS_fchownat
# define SYS_fchownat SYSNO_UNDEFINED
#endif

#ifndef SYS_fcntl
# define SYS_fcntl SYSNO_UNDEFINED
#endif

#ifndef SYS_fcntl64
# define SYS_fcntl64 SYSNO_UNDEFINED
#endif

#ifndef SYS_fdatasync
# define SYS_fdatasync SYSNO_UNDEFINED
#endif

#ifndef SYS_fgetxattr
# define SYS_fgetxattr SYSNO_UNDEFINED
#endif

#ifndef SYS_finit_module
# define SYS_finit_module SYSNO_UNDEFINED
#endif

#ifndef SYS_flistxattr
# define SYS_flistxattr SYSNO_UNDEFINED
#endif

#ifndef SYS_flock
# define SYS_flock SYSNO_UNDEFINED
#endif

#ifndef SYS_fork
# define SYS_fork SYSNO_UNDEFINED
#endif

#ifndef SYS_fp_udfiex_crtl
# define SYS_fp_udfiex_crtl SYSNO_UNDEFINED
#endif

#ifndef SYS_free_hugepages
# define SYS_free_hugepages SYSNO_UNDEFINED
#endif

#ifndef SYS_fremovexattr
# define SYS_fremovexattr SYSNO_UNDEFINED
#endif

#ifndef SYS_fsconfig
# define SYS_fsconfig SYSNO_UNDEFINED
#endif

#ifndef SYS_fsetxattr
# define SYS_fsetxattr SYSNO_UNDEFINED
#endif

#ifndef SYS_fsmount
# define SYS_fsmount SYSNO_UNDEFINED
#endif

#ifndef SYS_fsopen
# define SYS_fsopen SYSNO_UNDEFINED
#endif

#ifndef SYS_fspick
# define SYS_fspick SYSNO_UNDEFINED
#endif

#ifndef SYS_fstat
# define SYS_fstat SYSNO_UNDEFINED
#endif

#ifndef SYS_fstat64
# define SYS_fstat64 SYSNO_UNDEFINED
#endif

#ifndef SYS_fstatat64
# define SYS_fstatat64 SYSNO_UNDEFINED
#endif

#ifndef SYS_fstatfs
# define SYS_fstatfs SYSNO_UNDEFINED
#endif

#ifndef SYS_fstatfs64
# define SYS_fstatfs64 SYSNO_UNDEFINED
#endif

#ifndef SYS_fsync
# define SYS_fsync SYSNO_UNDEFINED
#endif

#ifndef SYS_ftime
# define SYS_ftime SYSNO_UNDEFINED
#endif

#ifndef SYS_ftruncate
# define SYS_ftruncate SYSNO_UNDEFINED
#endif

#ifndef SYS_ftruncate64
# define SYS_ftruncate64 SYSNO_UNDEFINED
#endif

#ifndef SYS_futex
# define SYS_futex SYSNO_UNDEFINED
#endif

#ifndef SYS_futex_time64
# define SYS_futex_time64 SYSNO_UNDEFINED
#endif

#ifndef SYS_futimesat
# define SYS_futimesat SYSNO_UNDEFINED
#endif

#ifndef SYS_get_kernel_syms
# define SYS_get_kernel_syms SYSNO_UNDEFINED
#endif

#ifndef SYS_get_mempolicy
# define SYS_get_mempolicy SYSNO_UNDEFINED
#endif

#ifndef SYS_get_robust_list
# define SYS_get_robust_list SYSNO_UNDEFINED
#endif

#ifndef SYS_get_thread_area
# define SYS_get_thread_area SYSNO_UNDEFINED
#endif

#ifndef SYS_get_tls
# define SYS_get_tls SYSNO_UNDEFINED
#endif

#ifndef SYS_getcpu
# define SYS_getcpu SYSNO_UNDEFINED
#endif

#ifndef SYS_getcwd
# define SYS_getcwd SYSNO_UNDEFINED
#endif

#ifndef SYS_getdents
# define SYS_getdents SYSNO_UNDEFINED
#endif

#ifndef SYS_getdents64
# define SYS_getdents64 SYSNO_UNDEFINED
#endif

#ifndef SYS_getdomainname
# define SYS_getdomainname SYSNO_UNDEFINED
#endif

#ifndef SYS_getdtablesize
# define SYS_getdtablesize SYSNO_UNDEFINED
#endif

#ifndef SYS_getegid
# define SYS_getegid SYSNO_UNDEFINED
#endif

#ifndef SYS_getegid32
# define SYS_getegid32 SYSNO_UNDEFINED
#endif

#ifndef SYS_geteuid
# define SYS_geteuid SYSNO_UNDEFINED
#endif

#ifndef SYS_geteuid32
# define SYS_geteuid32 SYSNO_UNDEFINED
#endif

#ifndef SYS_getgid
# define SYS_getgid SYSNO_UNDEFINED
#endif

#ifndef SYS_getgid32
# define SYS_getgid32 SYSNO_UNDEFINED
#endif

#ifndef SYS_getgroups
# define SYS_getgroups SYSNO_UNDEFINED
#endif

#ifndef SYS_getgroups32
# define SYS_getgroups32 SYSNO_UNDEFINED
#endif

#ifndef SYS_gethostname
# define SYS_gethostname SYSNO_UNDEFINED
#endif

#ifndef SYS_getitimer
# define SYS_getitimer SYSNO_UNDEFINED
#endif

#ifndef SYS_getpagesize
# define SYS_getpagesize SYSNO_UNDEFINED
#endif

#ifndef SYS_getpeername
# define SYS_getpeername SYSNO_UNDEFINED
#endif

#ifndef SYS_getpgid
# define SYS_getpgid SYSNO_UNDEFINED
#endif

#ifndef SYS_getpgrp
# define SYS_getpgrp SYSNO_UNDEFINED
#endif

#ifndef SYS_getpid
# define SYS_getpid SYSNO_UNDEFINED
#endif

#ifndef SYS_getpmsg
# define SYS_getpmsg SYSNO_UNDEFINED
#endif

#ifndef SYS_getppid
# define SYS_getppid SYSNO_UNDEFINED
#endif

#ifndef SYS_getpriority
# define SYS_getpriority SYSNO_UNDEFINED
#endif

#ifndef SYS_getrandom
# define SYS_getrandom SYSNO_UNDEFINED
#endif

#ifndef SYS_getresgid
# define SYS_getresgid SYSNO_UNDEFINED
#endif

#ifndef SYS_getresgid32
# define SYS_getresgid32 SYSNO_UNDEFINED
#endif

#ifndef SYS_getresuid
# define SYS_getresuid SYSNO_UNDEFINED
#endif

#ifndef SYS_getresuid32
# define SYS_getresuid32 SYSNO_UNDEFINED
#endif

#ifndef SYS_getrlimit
# define SYS_getrlimit SYSNO_UNDEFINED
#endif

#ifndef SYS_getrusage
# define SYS_getrusage SYSNO_UNDEFINED
#endif

#ifndef SYS_getsid
# define SYS_getsid SYSNO_UNDEFINED
#endif

#ifndef SYS_getsockname
# define SYS_getsockname SYSNO_UNDEFINED
#endif

#ifndef SYS_getsockopt
# define SYS_getsockopt SYSNO_UNDEFINED
#endif

#ifndef SYS_gettid
# define SYS_gettid SYSNO_UNDEFINED
#endif

#ifndef SYS_gettimeofday
# define SYS_gettimeofday SYSNO_UNDEFINED
#endif

#ifndef SYS_getuid
# define SYS_getuid SYSNO_UNDEFINED
#endif

#ifndef SYS_getuid32
# define SYS_getuid32 SYSNO_UNDEFINED
#endif

#ifndef SYS_getunwind
# define SYS_getunwind SYSNO_UNDEFINED
#endif

#ifndef SYS_getxattr
# define SYS_getxattr SYSNO_UNDEFINED
#endif

#ifndef SYS_getxgid
# define SYS_getxgid SYSNO_UNDEFINED
#endif

#ifndef SYS_getxpid
# define SYS_getxpid SYSNO_UNDEFINED
#endif

#ifndef SYS_getxuid
# define SYS_getxuid SYSNO_UNDEFINED
#endif

#ifndef SYS_gtty
# define SYS_gtty SYSNO_UNDEFINED
#endif

#ifndef SYS_idle
# define SYS_idle SYSNO_UNDEFINED
#endif

#ifndef SYS_init_module
# define SYS_init_module SYSNO_UNDEFINED
#endif

#ifndef SYS_inotify_add_watch
# define SYS_inotify_add_watch SYSNO_UNDEFINED
#endif

#ifndef SYS_inotify_init
# define SYS_inotify_init SYSNO_UNDEFINED
#endif

#ifndef SYS_inotify_init1
# define SYS_inotify_init1 SYSNO_UNDEFINED
#endif

#ifndef SYS_inotify_rm_watch
# define SYS_inotify_rm_watch SYSNO_UNDEFINED
#endif

#ifndef SYS_io_cancel
# define SYS_io_cancel SYSNO_UNDEFINED
#endif

#ifndef SYS_io_destroy
# define SYS_io_destroy SYSNO_UNDEFINED
#endif

#ifndef SYS_io_getevents
# define SYS_io_getevents SYSNO_UNDEFINED
#endif

#ifndef SYS_io_pgetevents
# define SYS_io_pgetevents SYSNO_UNDEFINED
#endif

#ifndef SYS_io_pgetevents_time64
# define SYS_io_pgetevents_time64 SYSNO_UNDEFINED
#endif

#ifndef SYS_io_setup
# define SYS_io_setup SYSNO_UNDEFINED
#endif

#ifndef SYS_io_submit
# define SYS_io_submit SYSNO_UNDEFINED
#endif

#ifndef SYS_io_uring_enter
# define SYS_io_uring_enter SYSNO_UNDEFINED
#endif

#ifndef SYS_io_uring_register
# define SYS_io_uring_register SYSNO_UNDEFINED
#endif

#ifndef SYS_io_uring_setup
# define SYS_io_uring_setup SYSNO_UNDEFINED
#endif

#ifndef SYS_ioctl
# define SYS_ioctl SYSNO_UNDEFINED
#endif

#ifndef SYS_ioperm
# define SYS_ioperm SYSNO_UNDEFINED
#endif

#ifndef SYS_iopl
# define SYS_iopl SYSNO_UNDEFINED
#endif

#ifndef SYS_ioprio_get
# define SYS_ioprio_get SYSNO_UNDEFINED
#endif

#ifndef SYS_ioprio_set
# define SYS_ioprio_set SYSNO_UNDEFINED
#endif

#ifndef SYS_ipc
# define SYS_ipc SYSNO_UNDEFINED
#endif

#ifndef SYS_kcmp
# define SYS_kcmp SYSNO_UNDEFINED
#endif

#ifndef SYS_kern_features
# define SYS_kern_features SYSNO_UNDEFINED
#endif

#ifndef SYS_kexec_file_load
# define SYS_kexec_file_load SYSNO_UNDEFINED
#endif

#ifndef SYS_kexec_load
# define SYS_kexec_load SYSNO_UNDEFINED
#endif

#ifndef SYS_keyctl
# define SYS_keyctl SYSNO_UNDEFINED
#endif

#ifndef SYS_kill
# define SYS_kill SYSNO_UNDEFINED
#endif

#ifndef SYS_lchown
# define SYS_lchown SYSNO_UNDEFINED
#endif

#ifndef SYS_lchown32
# define SYS_lchown32 SYSNO_UNDEFINED
#endif

#ifndef SYS_lgetxattr
# define SYS_lgetxattr SYSNO_UNDEFINED
#endif

#ifndef SYS_link
# define SYS_link SYSNO_UNDEFINED
#endif

#ifndef SYS_linkat
# define SYS_linkat SYSNO_UNDEFINED
#endif

#ifndef SYS_listen
# define SYS_listen SYSNO_UNDEFINED
#endif

#ifndef SYS_listxattr
# define SYS_listxattr SYSNO_UNDEFINED
#endif

#ifndef SYS_llistxattr
# define SYS_llistxattr SYSNO_UNDEFINED
#endif

#ifndef SYS_llseek
# define SYS_llseek SYSNO_UNDEFINED
#endif

#ifndef SYS_lock
# define SYS_lock SYSNO_UNDEFINED
#endif

#ifndef SYS_lookup_dcookie
# define SYS_lookup_dcookie SYSNO_UNDEFINED
#endif

#ifndef SYS_lremovexattr
# define SYS_lremovexattr SYSNO_UNDEFINED
#endif

#ifndef SYS_lseek
# define SYS_lseek SYSNO_UNDEFINED
#endif

#ifndef SYS_lsetxattr
# define SYS_lsetxattr SYSNO_UNDEFINED
#endif

#ifndef SYS_lstat
# define SYS_lstat SYSNO_UNDEFINED
#endif

#ifndef SYS_lstat64
# define SYS_lstat64 SYSNO_UNDEFINED
#endif

#ifndef SYS_madvise
# define SYS_madvise SYSNO_UNDEFINED
#endif

#ifndef SYS_mbind
# define SYS_mbind SYSNO_UNDEFINED
#endif

#ifndef SYS_membarrier
# define SYS_membarrier SYSNO_UNDEFINED
#endif

#ifndef SYS_memfd_create
# define SYS_memfd_create SYSNO_UNDEFINED
#endif

#ifndef SYS_memory_ordering
# define SYS_memory_ordering SYSNO_UNDEFINED
#endif

#ifndef SYS_migrate_pages
# define SYS_migrate_pages SYSNO_UNDEFINED
#endif

#ifndef SYS_mincore
# define SYS_mincore SYSNO_UNDEFINED
#endif

#ifndef SYS_mkdir
# define SYS_mkdir SYSNO_UNDEFINED
#endif

#ifndef SYS_mkdirat
# define SYS_mkdirat SYSNO_UNDEFINED
#endif

#ifndef SYS_mknod
# define SYS_mknod SYSNO_UNDEFINED
#endif

#ifndef SYS_mknodat
# define SYS_mknodat SYSNO_UNDEFINED
#endif

#ifndef SYS_mlock
# define SYS_mlock SYSNO_UNDEFINED
#endif

#ifndef SYS_mlock2
# define SYS_mlock2 SYSNO_UNDEFINED
#endif

#ifndef SYS_mlockall
# define SYS_mlockall SYSNO_UNDEFINED
#endif

#ifndef SYS_mmap
# define SYS_mmap SYSNO_UNDEFINED
#endif

#ifndef SYS_mmap2
# define SYS_mmap2 SYSNO_UNDEFINED
#endif

#ifndef SYS_modify_ldt
# define SYS_modify_ldt SYSNO_UNDEFINED
#endif

#ifndef SYS_mount
# define SYS_mount SYSNO_UNDEFINED
#endif

#ifndef SYS_move_mount
# define SYS_move_mount SYSNO_UNDEFINED
#endif

#ifndef SYS_move_pages
# define SYS_move_pages SYSNO_UNDEFINED
#endif

#ifndef SYS_mprotect
# define SYS_mprotect SYSNO_UNDEFINED
#endif

#ifndef SYS_mpx
# define SYS_mpx SYSNO_UNDEFINED
#endif

#ifndef SYS_mq_getsetattr
# define SYS_mq_getsetattr SYSNO_UNDEFINED
#endif

#ifndef SYS_mq_notify
# define SYS_mq_notify SYSNO_UNDEFINED
#endif

#ifndef SYS_mq_open
# define SYS_mq_open SYSNO_UNDEFINED
#endif

#ifndef SYS_mq_timedreceive
# define SYS_mq_timedreceive SYSNO_UNDEFINED
#endif

#ifndef SYS_mq_timedreceive_time64
# define SYS_mq_timedreceive_time64 SYSNO_UNDEFINED
#endif

#ifndef SYS_mq_timedsend
# define SYS_mq_timedsend SYSNO_UNDEFINED
#endif

#ifndef SYS_mq_timedsend_time64
# define SYS_mq_timedsend_time64 SYSNO_UNDEFINED
#endif

#ifndef SYS_mq_unlink
# define SYS_mq_unlink SYSNO_UNDEFINED
#endif

#ifndef SYS_mremap
# define SYS_mremap SYSNO_UNDEFINED
#endif

#ifndef SYS_msgctl
# define SYS_msgctl SYSNO_UNDEFINED
#endif

#ifndef SYS_msgget
# define SYS_msgget SYSNO_UNDEFINED
#endif

#ifndef SYS_msgrcv
# define SYS_msgrcv SYSNO_UNDEFINED
#endif

#ifndef SYS_msgsnd
# define SYS_msgsnd SYSNO_UNDEFINED
#endif

#ifndef SYS_msync
# define SYS_msync SYSNO_UNDEFINED
#endif

#ifndef SYS_multiplexer
# define SYS_multiplexer SYSNO_UNDEFINED
#endif

#ifndef SYS_munlock
# define SYS_munlock SYSNO_UNDEFINED
#endif

#ifndef SYS_munlockall
# define SYS_munlockall SYSNO_UNDEFINED
#endif

#ifndef SYS_munmap
# define SYS_munmap SYSNO_UNDEFINED
#endif

#ifndef SYS_name_to_handle_at
# define SYS_name_to_handle_at SYSNO_UNDEFINED
#endif

#ifndef SYS_nanosleep
# define SYS_nanosleep SYSNO_UNDEFINED
#endif

#ifndef SYS_newfstatat
# define SYS_newfstatat SYSNO_UNDEFINED
#endif

#ifndef SYS_nfsservctl
# define SYS_nfsservctl SYSNO_UNDEFINED
#endif

#ifndef SYS_ni_syscall
# define SYS_ni_syscall SYSNO_UNDEFINED
#endif

#ifndef SYS_nice
# define SYS_nice SYSNO_UNDEFINED
#endif

#ifndef SYS_old_adjtimex
# define SYS_old_adjtimex SYSNO_UNDEFINED
#endif

#ifndef SYS_old_getpagesize
# define SYS_old_getpagesize SYSNO_UNDEFINED
#endif

#ifndef SYS_oldfstat
# define SYS_oldfstat SYSNO_UNDEFINED
#endif

#ifndef SYS_oldlstat
# define SYS_oldlstat SYSNO_UNDEFINED
#endif

#ifndef SYS_oldolduname
# define SYS_oldolduname SYSNO_UNDEFINED
#endif

#ifndef SYS_oldstat
# define SYS_oldstat SYSNO_UNDEFINED
#endif

#ifndef SYS_oldumount
# define SYS_oldumount SYSNO_UNDEFINED
#endif

#ifndef SYS_olduname
# define SYS_olduname SYSNO_UNDEFINED
#endif

#ifndef SYS_open
# define SYS_open SYSNO_UNDEFINED
#endif

#ifndef SYS_open_by_handle_at
# define SYS_open_by_handle_at SYSNO_UNDEFINED
#endif

#ifndef SYS_open_tree
# define SYS_open_tree SYSNO_UNDEFINED
#endif

#ifndef SYS_openat
# define SYS_openat SYSNO_UNDEFINED
#endif

#ifndef SYS_openat2
# define SYS_openat2 SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_adjtime
# define SYS_osf_adjtime SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_afs_syscall
# define SYS_osf_afs_syscall SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_alt_plock
# define SYS_osf_alt_plock SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_alt_setsid
# define SYS_osf_alt_setsid SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_alt_sigpending
# define SYS_osf_alt_sigpending SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_asynch_daemon
# define SYS_osf_asynch_daemon SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_audcntl
# define SYS_osf_audcntl SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_audgen
# define SYS_osf_audgen SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_chflags
# define SYS_osf_chflags SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_execve
# define SYS_osf_execve SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_exportfs
# define SYS_osf_exportfs SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_fchflags
# define SYS_osf_fchflags SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_fdatasync
# define SYS_osf_fdatasync SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_fpathconf
# define SYS_osf_fpathconf SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_fstat
# define SYS_osf_fstat SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_fstatfs
# define SYS_osf_fstatfs SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_fstatfs64
# define SYS_osf_fstatfs64 SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_fuser
# define SYS_osf_fuser SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_getaddressconf
# define SYS_osf_getaddressconf SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_getdirentries
# define SYS_osf_getdirentries SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_getdomainname
# define SYS_osf_getdomainname SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_getfh
# define SYS_osf_getfh SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_getfsstat
# define SYS_osf_getfsstat SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_gethostid
# define SYS_osf_gethostid SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_getitimer
# define SYS_osf_getitimer SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_getlogin
# define SYS_osf_getlogin SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_getmnt
# define SYS_osf_getmnt SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_getrusage
# define SYS_osf_getrusage SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_getsysinfo
# define SYS_osf_getsysinfo SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_gettimeofday
# define SYS_osf_gettimeofday SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_kloadcall
# define SYS_osf_kloadcall SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_kmodcall
# define SYS_osf_kmodcall SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_lstat
# define SYS_osf_lstat SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_memcntl
# define SYS_osf_memcntl SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_mincore
# define SYS_osf_mincore SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_mount
# define SYS_osf_mount SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_mremap
# define SYS_osf_mremap SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_msfs_syscall
# define SYS_osf_msfs_syscall SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_msleep
# define SYS_osf_msleep SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_mvalid
# define SYS_osf_mvalid SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_mwakeup
# define SYS_osf_mwakeup SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_naccept
# define SYS_osf_naccept SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_nfssvc
# define SYS_osf_nfssvc SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_ngetpeername
# define SYS_osf_ngetpeername SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_ngetsockname
# define SYS_osf_ngetsockname SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_nrecvfrom
# define SYS_osf_nrecvfrom SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_nrecvmsg
# define SYS_osf_nrecvmsg SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_nsendmsg
# define SYS_osf_nsendmsg SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_ntp_adjtime
# define SYS_osf_ntp_adjtime SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_ntp_gettime
# define SYS_osf_ntp_gettime SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_creat
# define SYS_osf_old_creat SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_fstat
# define SYS_osf_old_fstat SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_getpgrp
# define SYS_osf_old_getpgrp SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_killpg
# define SYS_osf_old_killpg SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_lstat
# define SYS_osf_old_lstat SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_open
# define SYS_osf_old_open SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_sigaction
# define SYS_osf_old_sigaction SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_sigblock
# define SYS_osf_old_sigblock SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_sigreturn
# define SYS_osf_old_sigreturn SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_sigsetmask
# define SYS_osf_old_sigsetmask SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_sigvec
# define SYS_osf_old_sigvec SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_stat
# define SYS_osf_old_stat SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_vadvise
# define SYS_osf_old_vadvise SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_vtrace
# define SYS_osf_old_vtrace SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_old_wait
# define SYS_osf_old_wait SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_oldquota
# define SYS_osf_oldquota SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_pathconf
# define SYS_osf_pathconf SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_pid_block
# define SYS_osf_pid_block SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_pid_unblock
# define SYS_osf_pid_unblock SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_plock
# define SYS_osf_plock SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_priocntlset
# define SYS_osf_priocntlset SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_profil
# define SYS_osf_profil SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_proplist_syscall
# define SYS_osf_proplist_syscall SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_reboot
# define SYS_osf_reboot SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_revoke
# define SYS_osf_revoke SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_sbrk
# define SYS_osf_sbrk SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_security
# define SYS_osf_security SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_select
# define SYS_osf_select SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_set_program_attributes
# define SYS_osf_set_program_attributes SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_set_speculative
# define SYS_osf_set_speculative SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_sethostid
# define SYS_osf_sethostid SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_setitimer
# define SYS_osf_setitimer SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_setlogin
# define SYS_osf_setlogin SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_setsysinfo
# define SYS_osf_setsysinfo SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_settimeofday
# define SYS_osf_settimeofday SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_shmat
# define SYS_osf_shmat SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_signal
# define SYS_osf_signal SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_sigprocmask
# define SYS_osf_sigprocmask SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_sigsendset
# define SYS_osf_sigsendset SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_sigstack
# define SYS_osf_sigstack SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_sigwaitprim
# define SYS_osf_sigwaitprim SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_sstk
# define SYS_osf_sstk SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_stat
# define SYS_osf_stat SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_statfs
# define SYS_osf_statfs SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_statfs64
# define SYS_osf_statfs64 SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_subsys_info
# define SYS_osf_subsys_info SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_swapctl
# define SYS_osf_swapctl SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_swapon
# define SYS_osf_swapon SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_syscall
# define SYS_osf_syscall SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_sysinfo
# define SYS_osf_sysinfo SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_table
# define SYS_osf_table SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_uadmin
# define SYS_osf_uadmin SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_usleep_thread
# define SYS_osf_usleep_thread SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_uswitch
# define SYS_osf_uswitch SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_utc_adjtime
# define SYS_osf_utc_adjtime SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_utc_gettime
# define SYS_osf_utc_gettime SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_utimes
# define SYS_osf_utimes SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_utsname
# define SYS_osf_utsname SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_wait4
# define SYS_osf_wait4 SYSNO_UNDEFINED
#endif

#ifndef SYS_osf_waitid
# define SYS_osf_waitid SYSNO_UNDEFINED
#endif

#ifndef SYS_pause
# define SYS_pause SYSNO_UNDEFINED
#endif

#ifndef SYS_pciconfig_iobase
# define SYS_pciconfig_iobase SYSNO_UNDEFINED
#endif

#ifndef SYS_pciconfig_read
# define SYS_pciconfig_read SYSNO_UNDEFINED
#endif

#ifndef SYS_pciconfig_write
# define SYS_pciconfig_write SYSNO_UNDEFINED
#endif

#ifndef SYS_perf_event_open
# define SYS_perf_event_open SYSNO_UNDEFINED
#endif

#ifndef SYS_perfctr
# define SYS_perfctr SYSNO_UNDEFINED
#endif

#ifndef SYS_perfmonctl
# define SYS_perfmonctl SYSNO_UNDEFINED
#endif

#ifndef SYS_personality
# define SYS_personality SYSNO_UNDEFINED
#endif

#ifndef SYS_pidfd_getfd
# define SYS_pidfd_getfd SYSNO_UNDEFINED
#endif

#ifndef SYS_pidfd_open
# define SYS_pidfd_open SYSNO_UNDEFINED
#endif

#ifndef SYS_pidfd_send_signal
# define SYS_pidfd_send_signal SYSNO_UNDEFINED
#endif

#ifndef SYS_pipe
# define SYS_pipe SYSNO_UNDEFINED
#endif

#ifndef SYS_pipe2
# define SYS_pipe2 SYSNO_UNDEFINED
#endif

#ifndef SYS_pivot_root
# define SYS_pivot_root SYSNO_UNDEFINED
#endif

#ifndef SYS_pkey_alloc
# define SYS_pkey_alloc SYSNO_UNDEFINED
#endif

#ifndef SYS_pkey_free
# define SYS_pkey_free SYSNO_UNDEFINED
#endif

#ifndef SYS_pkey_mprotect
# define SYS_pkey_mprotect SYSNO_UNDEFINED
#endif

#ifndef SYS_poll
# define SYS_poll SYSNO_UNDEFINED
#endif

#ifndef SYS_ppoll
# define SYS_ppoll SYSNO_UNDEFINED
#endif

#ifndef SYS_ppoll_time64
# define SYS_ppoll_time64 SYSNO_UNDEFINED
#endif

#ifndef SYS_prctl
# define SYS_prctl SYSNO_UNDEFINED
#endif

#ifndef SYS_pread64
# define SYS_pread64 SYSNO_UNDEFINED
#endif

#ifndef SYS_preadv
# define SYS_preadv SYSNO_UNDEFINED
#endif

#ifndef SYS_preadv2
# define SYS_preadv2 SYSNO_UNDEFINED
#endif

#ifndef SYS_prlimit64
# define SYS_prlimit64 SYSNO_UNDEFINED
#endif

#ifndef SYS_process_vm_readv
# define SYS_process_vm_readv SYSNO_UNDEFINED
#endif

#ifndef SYS_process_vm_writev
# define SYS_process_vm_writev SYSNO_UNDEFINED
#endif

#ifndef SYS_prof
# define SYS_prof SYSNO_UNDEFINED
#endif

#ifndef SYS_profil
# define SYS_profil SYSNO_UNDEFINED
#endif

#ifndef SYS_pselect6
# define SYS_pselect6 SYSNO_UNDEFINED
#endif

#ifndef SYS_pselect6_time64
# define SYS_pselect6_time64 SYSNO_UNDEFINED
#endif

#ifndef SYS_ptrace
# define SYS_ptrace SYSNO_UNDEFINED
#endif

#ifndef SYS_putpmsg
# define SYS_putpmsg SYSNO_UNDEFINED
#endif

#ifndef SYS_pwrite64
# define SYS_pwrite64 SYSNO_UNDEFINED
#endif

#ifndef SYS_pwritev
# define SYS_pwritev SYSNO_UNDEFINED
#endif

#ifndef SYS_pwritev2
# define SYS_pwritev2 SYSNO_UNDEFINED
#endif

#ifndef SYS_query_module
# define SYS_query_module SYSNO_UNDEFINED
#endif

#ifndef SYS_quotactl
# define SYS_quotactl SYSNO_UNDEFINED
#endif

#ifndef SYS_read
# define SYS_read SYSNO_UNDEFINED
#endif

#ifndef SYS_readahead
# define SYS_readahead SYSNO_UNDEFINED
#endif

#ifndef SYS_readdir
# define SYS_readdir SYSNO_UNDEFINED
#endif

#ifndef SYS_readlink
# define SYS_readlink SYSNO_UNDEFINED
#endif

#ifndef SYS_readlinkat
# define SYS_readlinkat SYSNO_UNDEFINED
#endif

#ifndef SYS_readv
# define SYS_readv SYSNO_UNDEFINED
#endif

#ifndef SYS_reboot
# define SYS_reboot SYSNO_UNDEFINED
#endif

#ifndef SYS_recv
# define SYS_recv SYSNO_UNDEFINED
#endif

#ifndef SYS_recvfrom
# define SYS_recvfrom SYSNO_UNDEFINED
#endif

#ifndef SYS_recvmmsg
# define SYS_recvmmsg SYSNO_UNDEFINED
#endif

#ifndef SYS_recvmmsg_time64
# define SYS_recvmmsg_time64 SYSNO_UNDEFINED
#endif

#ifndef SYS_recvmsg
# define SYS_recvmsg SYSNO_UNDEFINED
#endif

#ifndef SYS_remap_file_pages
# define SYS_remap_file_pages SYSNO_UNDEFINED
#endif

#ifndef SYS_removexattr
# define SYS_removexattr SYSNO_UNDEFINED
#endif

#ifndef SYS_rename
# define SYS_rename SYSNO_UNDEFINED
#endif

#ifndef SYS_renameat
# define SYS_renameat SYSNO_UNDEFINED
#endif

#ifndef SYS_renameat2
# define SYS_renameat2 SYSNO_UNDEFINED
#endif

#ifndef SYS_request_key
# define SYS_request_key SYSNO_UNDEFINED
#endif

#ifndef SYS_restart_syscall
# define SYS_restart_syscall SYSNO_UNDEFINED
#endif

#ifndef SYS_riscv_flush_icache
# define SYS_riscv_flush_icache SYSNO_UNDEFINED
#endif

#ifndef SYS_rmdir
# define SYS_rmdir SYSNO_UNDEFINED
#endif

#ifndef SYS_rseq
# define SYS_rseq SYSNO_UNDEFINED
#endif

#ifndef SYS_rt_sigaction
# define SYS_rt_sigaction SYSNO_UNDEFINED
#endif

#ifndef SYS_rt_sigpending
# define SYS_rt_sigpending SYSNO_UNDEFINED
#endif

#ifndef SYS_rt_sigprocmask
# define SYS_rt_sigprocmask SYSNO_UNDEFINED
#endif

#ifndef SYS_rt_sigqueueinfo
# define SYS_rt_sigqueueinfo SYSNO_UNDEFINED
#endif

#ifndef SYS_rt_sigreturn
# define SYS_rt_sigreturn SYSNO_UNDEFINED
#endif

#ifndef SYS_rt_sigsuspend
# define SYS_rt_sigsuspend SYSNO_UNDEFINED
#endif

#ifndef SYS_rt_sigtimedwait
# define SYS_rt_sigtimedwait SYSNO_UNDEFINED
#endif

#ifndef SYS_rt_sigtimedwait_time64
# define SYS_rt_sigtimedwait_time64 SYSNO_UNDEFINED
#endif

#ifndef SYS_rt_tgsigqueueinfo
# define SYS_rt_tgsigqueueinfo SYSNO_UNDEFINED
#endif

#ifndef SYS_rtas
# define SYS_rtas SYSNO_UNDEFINED
#endif

#ifndef SYS_s390_guarded_storage
# define SYS_s390_guarded_storage SYSNO_UNDEFINED
#endif

#ifndef SYS_s390_pci_mmio_read
# define SYS_s390_pci_mmio_read SYSNO_UNDEFINED
#endif

#ifndef SYS_s390_pci_mmio_write
# define SYS_s390_pci_mmio_write SYSNO_UNDEFINED
#endif

#ifndef SYS_s390_runtime_instr
# define SYS_s390_runtime_instr SYSNO_UNDEFINED
#endif

#ifndef SYS_s390_sthyi
# define SYS_s390_sthyi SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_get_affinity
# define SYS_sched_get_affinity SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_get_priority_max
# define SYS_sched_get_priority_max SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_get_priority_min
# define SYS_sched_get_priority_min SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_getaffinity
# define SYS_sched_getaffinity SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_getattr
# define SYS_sched_getattr SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_getparam
# define SYS_sched_getparam SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_getscheduler
# define SYS_sched_getscheduler SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_rr_get_interval
# define SYS_sched_rr_get_interval SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_rr_get_interval_time64
# define SYS_sched_rr_get_interval_time64 SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_set_affinity
# define SYS_sched_set_affinity SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_setaffinity
# define SYS_sched_setaffinity SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_setattr
# define SYS_sched_setattr SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_setparam
# define SYS_sched_setparam SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_setscheduler
# define SYS_sched_setscheduler SYSNO_UNDEFINED
#endif

#ifndef SYS_sched_yield
# define SYS_sched_yield SYSNO_UNDEFINED
#endif

#ifndef SYS_seccomp
# define SYS_seccomp SYSNO_UNDEFINED
#endif

#ifndef SYS_security
# define SYS_security SYSNO_UNDEFINED
#endif

#ifndef SYS_select
# define SYS_select SYSNO_UNDEFINED
#endif

#ifndef SYS_semctl
# define SYS_semctl SYSNO_UNDEFINED
#endif

#ifndef SYS_semget
# define SYS_semget SYSNO_UNDEFINED
#endif

#ifndef SYS_semop
# define SYS_semop SYSNO_UNDEFINED
#endif

#ifndef SYS_semtimedop
# define SYS_semtimedop SYSNO_UNDEFINED
#endif

#ifndef SYS_semtimedop_time64
# define SYS_semtimedop_time64 SYSNO_UNDEFINED
#endif

#ifndef SYS_send
# define SYS_send SYSNO_UNDEFINED
#endif

#ifndef SYS_sendfile
# define SYS_sendfile SYSNO_UNDEFINED
#endif

#ifndef SYS_sendfile64
# define SYS_sendfile64 SYSNO_UNDEFINED
#endif

#ifndef SYS_sendmmsg
# define SYS_sendmmsg SYSNO_UNDEFINED
#endif

#ifndef SYS_sendmsg
# define SYS_sendmsg SYSNO_UNDEFINED
#endif

#ifndef SYS_sendto
# define SYS_sendto SYSNO_UNDEFINED
#endif

#ifndef SYS_set_mempolicy
# define SYS_set_mempolicy SYSNO_UNDEFINED
#endif

#ifndef SYS_set_robust_list
# define SYS_set_robust_list SYSNO_UNDEFINED
#endif

#ifndef SYS_set_thread_area
# define SYS_set_thread_area SYSNO_UNDEFINED
#endif

#ifndef SYS_set_tid_address
# define SYS_set_tid_address SYSNO_UNDEFINED
#endif

#ifndef SYS_set_tls
# define SYS_set_tls SYSNO_UNDEFINED
#endif

#ifndef SYS_setdomainname
# define SYS_setdomainname SYSNO_UNDEFINED
#endif

#ifndef SYS_setfsgid
# define SYS_setfsgid SYSNO_UNDEFINED
#endif

#ifndef SYS_setfsgid32
# define SYS_setfsgid32 SYSNO_UNDEFINED
#endif

#ifndef SYS_setfsuid
# define SYS_setfsuid SYSNO_UNDEFINED
#endif

#ifndef SYS_setfsuid32
# define SYS_setfsuid32 SYSNO_UNDEFINED
#endif

#ifndef SYS_setgid
# define SYS_setgid SYSNO_UNDEFINED
#endif

#ifndef SYS_setgid32
# define SYS_setgid32 SYSNO_UNDEFINED
#endif

#ifndef SYS_setgroups
# define SYS_setgroups SYSNO_UNDEFINED
#endif

#ifndef SYS_setgroups32
# define SYS_setgroups32 SYSNO_UNDEFINED
#endif

#ifndef SYS_sethae
# define SYS_sethae SYSNO_UNDEFINED
#endif

#ifndef SYS_sethostname
# define SYS_sethostname SYSNO_UNDEFINED
#endif

#ifndef SYS_setitimer
# define SYS_setitimer SYSNO_UNDEFINED
#endif

#ifndef SYS_setns
# define SYS_setns SYSNO_UNDEFINED
#endif

#ifndef SYS_setpgid
# define SYS_setpgid SYSNO_UNDEFINED
#endif

#ifndef SYS_setpgrp
# define SYS_setpgrp SYSNO_UNDEFINED
#endif

#ifndef SYS_setpriority
# define SYS_setpriority SYSNO_UNDEFINED
#endif

#ifndef SYS_setregid
# define SYS_setregid SYSNO_UNDEFINED
#endif

#ifndef SYS_setregid32
# define SYS_setregid32 SYSNO_UNDEFINED
#endif

#ifndef SYS_setresgid
# define SYS_setresgid SYSNO_UNDEFINED
#endif

#ifndef SYS_setresgid32
# define SYS_setresgid32 SYSNO_UNDEFINED
#endif

#ifndef SYS_setresuid
# define SYS_setresuid SYSNO_UNDEFINED
#endif

#ifndef SYS_setresuid32
# define SYS_setresuid32 SYSNO_UNDEFINED
#endif

#ifndef SYS_setreuid
# define SYS_setreuid SYSNO_UNDEFINED
#endif

#ifndef SYS_setreuid32
# define SYS_setreuid32 SYSNO_UNDEFINED
#endif

#ifndef SYS_setrlimit
# define SYS_setrlimit SYSNO_UNDEFINED
#endif

#ifndef SYS_setsid
# define SYS_setsid SYSNO_UNDEFINED
#endif

#ifndef SYS_setsockopt
# define SYS_setsockopt SYSNO_UNDEFINED
#endif

#ifndef SYS_settimeofday
# define SYS_settimeofday SYSNO_UNDEFINED
#endif

#ifndef SYS_setuid
# define SYS_setuid SYSNO_UNDEFINED
#endif

#ifndef SYS_setuid32
# define SYS_setuid32 SYSNO_UNDEFINED
#endif

#ifndef SYS_setxattr
# define SYS_setxattr SYSNO_UNDEFINED
#endif

#ifndef SYS_sgetmask
# define SYS_sgetmask SYSNO_UNDEFINED
#endif

#ifndef SYS_shmat
# define SYS_shmat SYSNO_UNDEFINED
#endif

#ifndef SYS_shmctl
# define SYS_shmctl SYSNO_UNDEFINED
#endif

#ifndef SYS_shmdt
# define SYS_shmdt SYSNO_UNDEFINED
#endif

#ifndef SYS_shmget
# define SYS_shmget SYSNO_UNDEFINED
#endif

#ifndef SYS_shutdown
# define SYS_shutdown SYSNO_UNDEFINED
#endif

#ifndef SYS_sigaction
# define SYS_sigaction SYSNO_UNDEFINED
#endif

#ifndef SYS_sigaltstack
# define SYS_sigaltstack SYSNO_UNDEFINED
#endif

#ifndef SYS_signal
# define SYS_signal SYSNO_UNDEFINED
#endif

#ifndef SYS_signalfd
# define SYS_signalfd SYSNO_UNDEFINED
#endif

#ifndef SYS_signalfd4
# define SYS_signalfd4 SYSNO_UNDEFINED
#endif

#ifndef SYS_sigpending
# define SYS_sigpending SYSNO_UNDEFINED
#endif

#ifndef SYS_sigprocmask
# define SYS_sigprocmask SYSNO_UNDEFINED
#endif

#ifndef SYS_sigreturn
# define SYS_sigreturn SYSNO_UNDEFINED
#endif

#ifndef SYS_sigsuspend
# define SYS_sigsuspend SYSNO_UNDEFINED
#endif

#ifndef SYS_socket
# define SYS_socket SYSNO_UNDEFINED
#endif

#ifndef SYS_socketcall
# define SYS_socketcall SYSNO_UNDEFINED
#endif

#ifndef SYS_socketpair
# define SYS_socketpair SYSNO_UNDEFINED
#endif

#ifndef SYS_splice
# define SYS_splice SYSNO_UNDEFINED
#endif

#ifndef SYS_spu_create
# define SYS_spu_create SYSNO_UNDEFINED
#endif

#ifndef SYS_spu_run
# define SYS_spu_run SYSNO_UNDEFINED
#endif

#ifndef SYS_ssetmask
# define SYS_ssetmask SYSNO_UNDEFINED
#endif

#ifndef SYS_stat
# define SYS_stat SYSNO_UNDEFINED
#endif

#ifndef SYS_stat64
# define SYS_stat64 SYSNO_UNDEFINED
#endif

#ifndef SYS_statfs
# define SYS_statfs SYSNO_UNDEFINED
#endif

#ifndef SYS_statfs64
# define SYS_statfs64 SYSNO_UNDEFINED
#endif

#ifndef SYS_statx
# define SYS_statx SYSNO_UNDEFINED
#endif

#ifndef SYS_stime
# define SYS_stime SYSNO_UNDEFINED
#endif

#ifndef SYS_stty
# define SYS_stty SYSNO_UNDEFINED
#endif

#ifndef SYS_subpage_prot
# define SYS_subpage_prot SYSNO_UNDEFINED
#endif

#ifndef SYS_swapcontext
# define SYS_swapcontext SYSNO_UNDEFINED
#endif

#ifndef SYS_swapoff
# define SYS_swapoff SYSNO_UNDEFINED
#endif

#ifndef SYS_swapon
# define SYS_swapon SYSNO_UNDEFINED
#endif

#ifndef SYS_switch_endian
# define SYS_switch_endian SYSNO_UNDEFINED
#endif

#ifndef SYS_symlink
# define SYS_symlink SYSNO_UNDEFINED
#endif

#ifndef SYS_symlinkat
# define SYS_symlinkat SYSNO_UNDEFINED
#endif

#ifndef SYS_sync
# define SYS_sync SYSNO_UNDEFINED
#endif

#ifndef SYS_sync_file_range
# define SYS_sync_file_range SYSNO_UNDEFINED
#endif

#ifndef SYS_sync_file_range2
# define SYS_sync_file_range2 SYSNO_UNDEFINED
#endif

#ifndef SYS_syncfs
# define SYS_syncfs SYSNO_UNDEFINED
#endif

#ifndef SYS_sys_debug_setcontext
# define SYS_sys_debug_setcontext SYSNO_UNDEFINED
#endif

#ifndef SYS_sys_epoll_create
# define SYS_sys_epoll_create SYSNO_UNDEFINED
#endif

#ifndef SYS_sys_epoll_ctl
# define SYS_sys_epoll_ctl SYSNO_UNDEFINED
#endif

#ifndef SYS_sys_epoll_wait
# define SYS_sys_epoll_wait SYSNO_UNDEFINED
#endif

#ifndef SYS_syscall
# define SYS_syscall SYSNO_UNDEFINED
#endif

#ifndef SYS_sysfs
# define SYS_sysfs SYSNO_UNDEFINED
#endif

#ifndef SYS_sysinfo
# define SYS_sysinfo SYSNO_UNDEFINED
#endif

#ifndef SYS_syslog
# define SYS_syslog SYSNO_UNDEFINED
#endif

#ifndef SYS_sysmips
# define SYS_sysmips SYSNO_UNDEFINED
#endif

#ifndef SYS_tee
# define SYS_tee SYSNO_UNDEFINED
#endif

#ifndef SYS_tgkill
# define SYS_tgkill SYSNO_UNDEFINED
#endif

#ifndef SYS_time
# define SYS_time SYSNO_UNDEFINED
#endif

#ifndef SYS_timer_create
# define SYS_timer_create SYSNO_UNDEFINED
#endif

#ifndef SYS_timer_delete
# define SYS_timer_delete SYSNO_UNDEFINED
#endif

#ifndef SYS_timer_getoverrun
# define SYS_timer_getoverrun SYSNO_UNDEFINED
#endif

#ifndef SYS_timer_gettime
# define SYS_timer_gettime SYSNO_UNDEFINED
#endif

#ifndef SYS_timer_gettime64
# define SYS_timer_gettime64 SYSNO_UNDEFINED
#endif

#ifndef SYS_timer_settime
# define SYS_timer_settime SYSNO_UNDEFINED
#endif

#ifndef SYS_timer_settime64
# define SYS_timer_settime64 SYSNO_UNDEFINED
#endif

#ifndef SYS_timerfd
# define SYS_timerfd SYSNO_UNDEFINED
#endif

#ifndef SYS_timerfd_create
# define SYS_timerfd_create SYSNO_UNDEFINED
#endif

#ifndef SYS_timerfd_gettime
# define SYS_timerfd_gettime SYSNO_UNDEFINED
#endif

#ifndef SYS_timerfd_gettime64
# define SYS_timerfd_gettime64 SYSNO_UNDEFINED
#endif

#ifndef SYS_timerfd_settime
# define SYS_timerfd_settime SYSNO_UNDEFINED
#endif

#ifndef SYS_timerfd_settime64
# define SYS_timerfd_settime64 SYSNO_UNDEFINED
#endif

#ifndef SYS_times
# define SYS_times SYSNO_UNDEFINED
#endif

#ifndef SYS_tkill
# define SYS_tkill SYSNO_UNDEFINED
#endif

#ifndef SYS_truncate
# define SYS_truncate SYSNO_UNDEFINED
#endif

#ifndef SYS_truncate64
# define SYS_truncate64 SYSNO_UNDEFINED
#endif

#ifndef SYS_tuxcall
# define SYS_tuxcall SYSNO_UNDEFINED
#endif

#ifndef SYS_udftrap
# define SYS_udftrap SYSNO_UNDEFINED
#endif

#ifndef SYS_ugetrlimit
# define SYS_ugetrlimit SYSNO_UNDEFINED
#endif

#ifndef SYS_ulimit
# define SYS_ulimit SYSNO_UNDEFINED
#endif

#ifndef SYS_umask
# define SYS_umask SYSNO_UNDEFINED
#endif

#ifndef SYS_umount
# define SYS_umount SYSNO_UNDEFINED
#endif

#ifndef SYS_umount2
# define SYS_umount2 SYSNO_UNDEFINED
#endif

#ifndef SYS_uname
# define SYS_uname SYSNO_UNDEFINED
#endif

#ifndef SYS_unlink
# define SYS_unlink SYSNO_UNDEFINED
#endif

#ifndef SYS_unlinkat
# define SYS_unlinkat SYSNO_UNDEFINED
#endif

#ifndef SYS_unshare
# define SYS_unshare SYSNO_UNDEFINED
#endif

#ifndef SYS_uselib
# define SYS_uselib SYSNO_UNDEFINED
#endif

#ifndef SYS_userfaultfd
# define SYS_userfaultfd SYSNO_UNDEFINED
#endif

#ifndef SYS_usr26
# define SYS_usr26 SYSNO_UNDEFINED
#endif

#ifndef SYS_usr32
# define SYS_usr32 SYSNO_UNDEFINED
#endif

#ifndef SYS_ustat
# define SYS_ustat SYSNO_UNDEFINED
#endif

#ifndef SYS_utime
# define SYS_utime SYSNO_UNDEFINED
#endif

#ifndef SYS_utimensat
# define SYS_utimensat SYSNO_UNDEFINED
#endif

#ifndef SYS_utimensat_time64
# define SYS_utimensat_time64 SYSNO_UNDEFINED
#endif

#ifndef SYS_utimes
# define SYS_utimes SYSNO_UNDEFINED
#endif

#ifndef SYS_utrap_install
# define SYS_utrap_install SYSNO_UNDEFINED
#endif

#ifndef SYS_vfork
# define SYS_vfork SYSNO_UNDEFINED
#endif

#ifndef SYS_vhangup
# define SYS_vhangup SYSNO_UNDEFINED
#endif

#ifndef SYS_vm86
# define SYS_vm86 SYSNO_UNDEFINED
#endif

#ifndef SYS_vm86old
# define SYS_vm86old SYSNO_UNDEFINED
#endif

#ifndef SYS_vmsplice
# define SYS_vmsplice SYSNO_UNDEFINED
#endif

#ifndef SYS_vserver
# define SYS_vserver SYSNO_UNDEFINED
#endif

#ifndef SYS_wait4
# define SYS_wait4 SYSNO_UNDEFINED
#endif

#ifndef SYS_waitid
# define SYS_waitid SYSNO_UNDEFINED
#endif

#ifndef SYS_waitpid
# define SYS_waitpid SYSNO_UNDEFINED
#endif

#ifndef SYS_waittid
# define SYS_waittid SYSNO_UNDEFINED
#endif

#ifndef SYS_write
# define SYS_write SYSNO_UNDEFINED
#endif

#ifndef SYS_writev
# define SYS_writev SYSNO_UNDEFINED
#endif

#define SYS_test_return_value 350
#define SYS_test_arg_copying  351
