#include "common_filters.h"

#define SYSFILTER_CHECK_FD(ti, fd) \
    if (fd < 0 || fd >= NUM_FDS) { } \
    else if (sf_data.fd_domain_mapping[fd] == FD_DOMAIN_NONE_OR_CLOSED) { \
        PREPEND_TO_DEBUG_BUFFER(COLOR_RED "ERROR: FD %d was not open" COLOR_RESET "\n", fd); \
        /*SYSFILTER_RETURN(ti, -EBADFD);*/ \
    } \

#define SYSFILTER_REGISTER_FD(fd) \
    /* let the user handle error / errno */ \
    if (fd < 0) { \
        return; \
    } \
    assert(fd < NUM_FDS); \
    sf_data.fd_domain_mapping[fd] = ti->did;

#define WRAPPER_FD(pos_fd) \
static void _sf_wrapper_fd_##pos_fd(trace_info_t *ti) { \
    DEBUG_FILTER(); \
    \
    if (IS_SYSCALL_ENTER(ti)) { \
        int fd = (int)ti->args[pos_fd]; \
        SYSFILTER_CHECK_FD(ti, fd); \
    } \
}
//------------------------------------------------------------------------------

static void PK_CODE _sf_sys_open(trace_info_t *ti)
{
    if (IS_SYSCALL_ENTER(ti)) {
        // need to check dirfd
        if (ti->syscall_nr == SYS_openat || ti->syscall_nr == SYS_openat2) {
            int dirfd = (int)ti->args[0];
            SYSFILTER_CHECK_FD(ti, dirfd);
        }
    }
    else {
        // check absolute path in procfs
        int fd = ti->return_value;
        if (fd < 0) {
            SYSFILTER_RETURN(ti, ti->return_value);
        }

        char path[PATH_MAX];
        if (_fd_path(fd, path) != 0) {
            ERROR_FAIL("file descriptor not valid");
        }

        int ret = _sanitize_path(ti, path);
        if (ret != 0) {
            // path points to procfd, cannot mark fd as opened
            close(fd);
            SYSFILTER_RETURN(ti, ret);
        }

        // mark fd to be opened
        sf_data.fd_domain_mapping[fd] = ti->did;
    }
}
//------------------------------------------------------------------------------

static void PK_CODE _sf_sys_accept(trace_info_t *ti)
{
    if (IS_SYSCALL_ENTER(ti)) {
        int oldfd = (int)ti->args[0];
        SYSFILTER_CHECK_FD(ti, oldfd);
    }
    else {
        SYSFILTER_REGISTER_FD(ti->return_value);
    }
}
//------------------------------------------------------------------------------

static void PK_CODE _sf_sys_socket(trace_info_t *ti)
{
    if (IS_SYSCALL_ENTER(ti)) {
    }
    else {
        SYSFILTER_REGISTER_FD(ti->return_value);
    }
}
//------------------------------------------------------------------------------

// close(fd);
static void PK_CODE _sf_sys_close(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (IS_SYSCALL_ENTER(ti)) {
        //int fd = (int)ti->args[0];
        //PREPEND_TO_DEBUG_BUFFER("sf_data.fd_domain_mapping[%d] = %d\n", fd, sf_data.fd_domain_mapping[fd]);
        //NOTE: we are not using SYSFILTER_CHECK_FD since there are other syscalls that can create a FD, which we have not traced
    }
    else {
        int ret = ti->return_value;
        if(0 == ret) {
            int fd = (int)ti->args[0];
            sf_data.fd_domain_mapping[fd] = FD_DOMAIN_NONE_OR_CLOSED;
        }
    }
}

// int dup(oldfd);
static void _sf_sys_dup(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (IS_SYSCALL_ENTER(ti)) {
        int oldfd = (int)ti->args[0];
        SYSFILTER_CHECK_FD(ti, oldfd);
    }
    else {
        SYSFILTER_REGISTER_FD(ti->return_value);
    }
}
//------------------------------------------------------------------------------

// int dup2(oldfd, newfd);
static void _sf_sys_dup2(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (IS_SYSCALL_ENTER(ti)) {
        int oldfd = (int)ti->args[0];
        int newfd = (int)ti->args[1];

        SYSFILTER_CHECK_FD(ti, oldfd);
        // do not need to check newfd
    }
    else {
        SYSFILTER_REGISTER_FD(ti->return_value);
    }
}

// int signalfd(int fd, const sigset_t *mask, int flags);
static void _sf_sys_signalfd(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (IS_SYSCALL_ENTER(ti)) {
        int fd = ti->args[0];
        SYSFILTER_CHECK_FD(ti, fd);
    }
    else {
        SYSFILTER_REGISTER_FD(ti->return_value);
    }
}
//------------------------------------------------------------------------------

//int pipe(int fildes[2]);
static void _sf_sys_pipe(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (IS_SYSCALL_ENTER(ti)) {
        // change pointer to arg page before syscall to prevent TOCTOU
        /*sf_arg_alloc(ti, 0, 2 * sizeof(int));*/
    }
    else {
        if(ti->return_value == 0){
            int *fildes = (int *)ti->args[0];

            SYSFILTER_REGISTER_FD(fildes[0]);
            SYSFILTER_REGISTER_FD(fildes[1]);
        }

        /*SYSFILTER_RETURN_IF_ERROR(ti, sf_arg_restore(ti, 0, 2 * sizeof(int)));*/
    }
}

// int socketpair(int domain, int type, int protocol, int sv[2]);
static void _sf_sys_socketpair(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (IS_SYSCALL_ENTER(ti)) {
        // change pointer to arg page before syscall to prevent TOCTOU
        /*sf_arg_alloc(ti, 3, 2 * sizeof(int));*/
    }
    else {
        int *sv = (int *)ti->args[3];

        SYSFILTER_REGISTER_FD(sv[0]);
        SYSFILTER_REGISTER_FD(sv[1]);

        /*SYSFILTER_RETURN_IF_ERROR(ti, sf_arg_restore(ti, 3, 2 * sizeof(int)));*/
    }
}
//------------------------------------------------------------------------------

// ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
// ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags);
static void _sf_wrapper_sendfile_tee(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (IS_SYSCALL_ENTER(ti)) {
        int oldfd = (int)ti->args[0];
        int newfd = (int)ti->args[1];

        SYSFILTER_CHECK_FD(ti, oldfd);
        SYSFILTER_CHECK_FD(ti, newfd);
    }
}
//------------------------------------------------------------------------------

// ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
// ssize_t copy_file_range(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
static void _sf_sys_splice_copy_file_range(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (IS_SYSCALL_ENTER(ti)) {
        int oldfd = (int)ti->args[0];
        int newfd = (int)ti->args[2];

        SYSFILTER_CHECK_FD(ti, oldfd);
        SYSFILTER_CHECK_FD(ti, newfd);
    }
}
//------------------------------------------------------------------------------

static void PK_CODE _sf_sys_fcntl(trace_info_t *ti)
{
    DEBUG_FILTER();

    int fildes = (int)ti->args[0];
    int cmd = (int)ti->args[1];

    if (IS_SYSCALL_ENTER(ti)) {
        SYSFILTER_CHECK_FD(ti, fildes);
    }
    else {
        if ((cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC)) {
            SYSFILTER_REGISTER_FD(ti->return_value);
        }
    }
}
//------------------------------------------------------------------------------

static void PK_CODE _sf_sys_truncate(trace_info_t *ti)
{
}
//------------------------------------------------------------------------------


#define ARG_COPY_PIPE        {{ARG_TYPE_ALLOC_RESTORE, 2 * sizeof(int)}}
#define ARG_COPY_SOCKET_PAIR {{0}, {0}, {0}, {ARG_TYPE_ALLOC_RESTORE, 2 * sizeof(int)}}

WRAPPER_FD(0);
WRAPPER_FD(4);

static sys_manual_t PK_DATA syscalls_manual[] = {
    { SYS_close,                 _sf_sys_close                                          },
    { SYS_pipe,                  _sf_sys_pipe,                  ARG_COPY_PIPE           },
    { SYS_pipe2,                 _sf_sys_pipe,                  ARG_COPY_PIPE           },
    { SYS_dup,                   _sf_sys_dup                                            },
    { SYS_dup2,                  _sf_sys_dup2,                                          },
    { SYS_dup3,                  _sf_sys_dup2                                           },
    { SYS_sendfile,              _sf_wrapper_sendfile_tee                               },
    { SYS_sendfile64,            _sf_wrapper_sendfile_tee                               },
    { SYS_splice,                _sf_sys_splice_copy_file_range                         },
    { SYS_copy_file_range,       _sf_sys_splice_copy_file_range                         },
    { SYS_tee,                   _sf_wrapper_sendfile_tee                               },
    { SYS_signalfd,              _sf_sys_signalfd                                       },
    { SYS_signalfd4,             _sf_sys_signalfd                                       },
    { SYS_socketpair,            _sf_sys_socketpair,            ARG_COPY_SOCKET_PAIR    },
    { SYS_fcntl,                 _sf_sys_fcntl                                          },
    { SYS_fcntl64,               _sf_sys_fcntl                                          },


    // -------------------------------------------------------
    // fd_0
    { SYS_read, _sf_wrapper_fd_0 },
    { SYS_write, _sf_wrapper_fd_0 },
    { SYS_fstat, _sf_wrapper_fd_0 },
    { SYS_lseek, _sf_wrapper_fd_0 },
    { SYS_pread64, _sf_wrapper_fd_0 },
    { SYS_pwrite64, _sf_wrapper_fd_0 },
    { SYS_readv, _sf_wrapper_fd_0 },
    { SYS_writev, _sf_wrapper_fd_0 },
    { SYS_flock, _sf_wrapper_fd_0 },
    { SYS_fsync, _sf_wrapper_fd_0 },
    { SYS_fdatasync, _sf_wrapper_fd_0 },
    { SYS_ftruncate, _sf_wrapper_fd_0 },
    { SYS_getdents, _sf_wrapper_fd_0 },
    { SYS_fchdir, _sf_wrapper_fd_0 },
    { SYS_fchmod, _sf_wrapper_fd_0 },
    { SYS_fchown, _sf_wrapper_fd_0 },
    { SYS_fstatfs, _sf_wrapper_fd_0 },
    { SYS_readahead, _sf_wrapper_fd_0 },
    { SYS_fsetxattr, _sf_wrapper_fd_0 },
    { SYS_fgetxattr, _sf_wrapper_fd_0 },
    { SYS_flistxattr, _sf_wrapper_fd_0 },
    { SYS_fremovexattr, _sf_wrapper_fd_0 },
    { SYS_getdents64, _sf_wrapper_fd_0 },
    { SYS_fadvise64, _sf_wrapper_fd_0 },
    { SYS_sync_file_range, _sf_wrapper_fd_0 },
    { SYS_vmsplice, _sf_wrapper_fd_0 },
    { SYS_fallocate, _sf_wrapper_fd_0 },
    { SYS_timerfd_settime, _sf_wrapper_fd_0 },
    { SYS_timerfd_gettime, _sf_wrapper_fd_0 },
    { SYS_preadv, _sf_wrapper_fd_0 },
    { SYS_pwritev, _sf_wrapper_fd_0 },
    { SYS_syncfs, _sf_wrapper_fd_0 },
    { SYS_setns, _sf_wrapper_fd_0 },
    { SYS_finit_module, _sf_wrapper_fd_0 },
    { SYS_preadv2, _sf_wrapper_fd_0 },
    { SYS_pwritev2, _sf_wrapper_fd_0 },

    // -------------------------------------------------------
    // network fd_0
    { SYS_connect, _sf_wrapper_fd_0 },
    { SYS_accept, _sf_sys_accept },
    { SYS_accept4, _sf_sys_accept },
    { SYS_sendto, _sf_wrapper_fd_0 },
    { SYS_recvfrom, _sf_wrapper_fd_0 },
    { SYS_sendmsg, _sf_wrapper_fd_0 },
    { SYS_recvmsg, _sf_wrapper_fd_0 },
    { SYS_shutdown, _sf_wrapper_fd_0 },
    { SYS_bind, _sf_wrapper_fd_0 },
    { SYS_listen, _sf_wrapper_fd_0 },
    { SYS_getsockname, _sf_wrapper_fd_0 },
    { SYS_getpeername, _sf_wrapper_fd_0 },
    { SYS_setsockopt, _sf_wrapper_fd_0 },
    { SYS_getsockopt, _sf_wrapper_fd_0 },
    { SYS_getpmsg, _sf_wrapper_fd_0 },
    { SYS_putpmsg, _sf_wrapper_fd_0 },
    { SYS_recvmmsg, _sf_wrapper_fd_0 },
    { SYS_recvmmsg_time64, _sf_wrapper_fd_0 },
    { SYS_sendmmsg, _sf_wrapper_fd_0 },

    // -------------------------------------------------------
    // fd_0_path_1
    { SYS_mkdirat, _sf_wrapper_fd_0 },
    { SYS_mknodat, _sf_wrapper_fd_0 },
    { SYS_fchownat, _sf_wrapper_fd_0 },
    { SYS_futimesat, _sf_wrapper_fd_0 },
    { SYS_unlinkat, _sf_wrapper_fd_0 },
    { SYS_readlinkat, _sf_wrapper_fd_0 },
    { SYS_fchmodat, _sf_wrapper_fd_0 },
    { SYS_faccessat, _sf_wrapper_fd_0 },
    { SYS_utimensat, _sf_wrapper_fd_0 },

    { SYS_socket,                _sf_sys_socket },
    { SYS_open,                  _sf_sys_open,          ARG_COPY_PATH_0 },
    { SYS_truncate,              _sf_sys_truncate,      ARG_COPY_PATH_0 },
    { SYS_openat,                _sf_sys_open,          ARG_COPY_PATH_1 },
    { SYS_name_to_handle_at,     SYSCALL_DENIED                         },
    { SYS_openat2,               _sf_sys_open,          ARG_COPY_PATH_1 },

    { SYS_ioctl,                 _sf_wrapper_fd_0                       },

    // for benchmarking
    { SYS_getpid,                _sf_empty_filter           }
};

void PK_CODE _sf_base_filters_open_init()
{
    DEBUG_SF("initializing self protection by open sanitization");

    _apply_custom_filters(syscalls_manual, sizeof(syscalls_manual) / sizeof(sys_manual_t));
    _check_core_pattern();
}
