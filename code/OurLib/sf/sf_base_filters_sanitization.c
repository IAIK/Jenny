#include "common_filters.h"
//------------------------------------------------------------------------------

#define SANITIZE_PATH_WRAPPER(pos_path) \
static void PK_CODE sanitize_path_##pos_path(trace_info_t *ti) { \
    if (IS_SYSCALL_ENTER(ti)) { \
        assert_ifdebug(pos_path + 1 < SYSCALL_ARG_COUNT); \
        /*SYSFILTER_RETURN_IF_ERROR(ti, sf_arg_string_copy(ti, pos_path));*/ \
        const char* path = (const char*)ti->args[pos_path]; \
        int ret = _sanitize_path(ti, path); \
        if(ret != 0) { \
            WARNING("Path %s not accessible by domain %d", path, ti->did); \
            SYSFILTER_RETURN(ti, ret); \
        } \
    } \
}
//------------------------------------------------------------------------------

#define SANITIZE_FD_PATH_WRAPPER(pos_fd, pos_path) \
static void PK_CODE sanitize_fd_##pos_fd##_path_##pos_path(trace_info_t *ti) { \
    if (IS_SYSCALL_ENTER(ti)) { \
        assert_ifdebug(pos_fd + 1 < SYSCALL_ARG_COUNT); \
        assert_ifdebug(pos_path + 1 < SYSCALL_ARG_COUNT); \
        /*SYSFILTER_RETURN_IF_ERROR(ti, sf_arg_string_copy(ti, pos_path));*/ \
        int fd = (int)ti->args[pos_fd]; \
        const char* path = (const char*)ti->args[pos_path]; \
        int ret = _sanitize_fd_path(ti, fd, path); \
        if(ret != 0) { \
            WARNING("Path %s not accessible by domain %d", path, ti->did); \
            SYSFILTER_RETURN(ti, ret); \
        } \
    } \
}
//------------------------------------------------------------------------------


SANITIZE_PATH_WRAPPER(0)
SANITIZE_FD_PATH_WRAPPER(0, 1)

#define SANITIZE_PATH_0             sanitize_path_0,            ARG_COPY_PATH_0
#define SANITIZE_FD_0_PATH_1        sanitize_fd_0_path_1,       ARG_COPY_PATH_1


static sys_manual_t PK_DATA syscalls_manual[] = {
    // file modification granting syscalls
    { SYS_open,                  SANITIZE_PATH_0            },
    //{ SYS_link,                  SANITIZE_PATH_0_PATH_1     }, // could create hardlink with different name, but not outside procfs
    { SYS_truncate,              SANITIZE_PATH_0            },
    //{ SYS_linkat,                SANITIZE_RENAMEAT_LINKAT   }, // could create hardlink with different name, but not outside procfs
    { SYS_openat,                SANITIZE_FD_0_PATH_1       },
    { SYS_name_to_handle_at,     SANITIZE_FD_0_PATH_1       },
    { SYS_openat2,               SANITIZE_FD_0_PATH_1       },

    // for benchmarking
    { SYS_getpid,                _sf_empty_filter           }
};

void PK_CODE _sf_base_filters_sanitization_init()
{
    DEBUG_SF("initializing self protection by path sanitization");

    _apply_custom_filters(syscalls_manual, sizeof(syscalls_manual) / sizeof(sys_manual_t));
    _check_core_pattern();
}
