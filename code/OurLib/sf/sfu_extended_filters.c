#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1 //Needed for pthread_getname_np and pthread_getattr_np and for link.h
#endif
#define GNU_SOURCE 1
#include "common_filters.h"
//#include <pthread.h>
#include <stdatomic.h>


/**
 * This file contains (monitor) filters for chrooting a domain
 * into a localstorage path.
 */

#define LOCALSTORAGE_DIR "/tmp/localstorage_%d"   // with appended uid

typedef struct _sf_localstorage_domain {
    // flags, indicating, if domain is initialized
    atomic_bool domain_initialized;
    // absolute cwds, where root is the base path
    char domain_cwd_mapping[PATH_MAX];
    // absolute base paths
    char domain_base_path_mapping[PATH_MAX];
} _sf_localstorage_domain;


typedef struct _sf_localstorage {
    /**
     * Lock, guarding the manipulations of paths under the 'sf_localstorage.localstorage_path'.
     * Guaranteeing consistent use of relative paths.
     *
     * A lock must be acquired for syscalls that use a path (e.g. open).
     * A lock must be acquired for syscalls that can change paths (rename, renameat, chdir).
     *
     * The lock is aquired before a path check and released after the syscall using the path.
     * The lock is recursive, so a parent domain the lock is already aquired.
     * Problem: A parent domain blocks the thread -> lock cannot be taken by other thread...
     */
    pthread_mutex_t path_mutex;

    // whether the filters are already initialized
    bool _sf_localstorage_filters_initialized;

    // absolute path to the 'LOCALSTORAGE_DIR'
    char localstorage_path[PATH_MAX];

    //per-domain data structures for localstorage filters
    _sf_localstorage_domain domains[NUM_DOMAINS];
} _sf_localstorage;
static _sf_localstorage sf_localstorage;

#define RETURN_ERROR(cmd) if ((cmd) == -1) { return -1; }


FORCE_INLINE void _domain_init(int did)
{
    char *path = sf_localstorage.domains[did].domain_base_path_mapping;
    assert(snprintf(path, PATH_MAX, "%s/%d", sf_localstorage.localstorage_path, did) <= PATH_MAX);

    // create domain directory
    struct stat sb;
    if (!(stat(path, &sb) == 0 && S_ISDIR(sb.st_mode))) {
        ERROR("localstorage path for domain %d does not exist: %s", did, path);
        DEBUG_SF("creating localstorage path for domain %d: %s", did, path);
        int ret = mkdir(path, 0777);
        //assert(ret == 0);
    }

    // setting initial cwd
    strcpy(sf_localstorage.domains[did].domain_cwd_mapping, "/cwd/");

    // creating inital cwd
    char cwd[PATH_MAX];
    assert(_path_join(path, "/cwd", cwd) == 0);
    mkdir(cwd, 0777);
    errno = 0;

    sf_localstorage.domains[did].domain_initialized = true;
}

FORCE_INLINE const char *_domain_base_path(int did)
{
    if (!sf_localstorage.domains[did].domain_initialized) {
        _domain_init(did);
    }
    return sf_localstorage.domains[did].domain_base_path_mapping;
}
//------------------------------------------------------------------------------

FORCE_INLINE void _domain_abs_cwd(int did, char *path)
{
    const char *base_path = _domain_base_path(did);
    assert(_path_join(base_path, sf_localstorage.domains[did].domain_cwd_mapping, path) == 0);
}
//------------------------------------------------------------------------------

FORCE_INLINE char *_domain_rel_cwd(int did)
{
    if (!sf_localstorage.domains[did].domain_initialized) {
        _domain_init(did);
    }
    return sf_localstorage.domains[did].domain_cwd_mapping;
}
//------------------------------------------------------------------------------

/**
 * @brief Resolves @p path of @p fd. AT_FDCWD resolved corresponding to @p did.
 */
FORCE_INLINE int _fd_path_domain(int did, int fd, char *path)
{
    if (fd == AT_FDCWD) {
        _domain_abs_cwd(did, path);
        return 0;
    }

    return _fd_path(fd, path);
}
//------------------------------------------------------------------------------

/**
 * @brief Joins base_path of the @p did and @p path to a @p new_path.
 */
FORCE_INLINE int _base_path_relative(int did, const char *path, char *new_path)
{
    const char *base_path = _domain_base_path(did);
    RETURN_ERROR(_path_join(base_path, path, new_path));
    return 0;
}
//------------------------------------------------------------------------------

/**
 * @brief Rewrites path, so it lays inside of corresponding base_path.
 *
 * @param did
 *        did, which this path should belong to
 * @param path
 *        path to rewrite (absolute or relative)
 * @param new_path
 *        outputting rewritten path
 * @return
 *        0 on sucess, or -1 on error (path too long)
 */
FORCE_INLINE int _rewrite_path(int did, const char *path, char *new_path)
{
    // ignore some special paths from rewriting
    if (strncmp(path, "/dev/", 5) == 0 || strncmp(path, "/usr/lib/", 9) == 0) {
        strcpy(new_path, path);
        return 0;
    }
    char full_path[PATH_MAX];
    if (_path_is_relative(path)) {
        // cwd must have '/' at start, so all '..' are normalized
        const char *cwd = _domain_rel_cwd(did);
        RETURN_ERROR(_path_join_normalize(cwd, path, full_path));
    }
    else {
        _path_normalize(path, full_path);
    }

    // full_path contains absolute path where root is the 'base_path'
    RETURN_ERROR(_base_path_relative(did, full_path, new_path));

    PREPEND_TO_DEBUG_BUFFER("rewriting path from %s to %s\n", path, new_path);
    return 0;
}
//------------------------------------------------------------------------------

/**
 * @brief Rewrites path with file descriptor, so it lays inside of
 *        the base_path of the @p did.
 *
 * @param did
 *        did, which this path should belong to
 * @param dirfd
 *        base of path (must already belong to @p did)
 * @param path
 *        path to rewrite (absolute or relative)
 * @param new_path
 *        outputting rewritten path (including path of @p dirfd)
 * @return
 *        0 on sucess, or -1 on error (path too long)
 */
FORCE_INLINE int _rewrite_fd_with_path(int did, int dirfd, const char *path, char *new_path)
{
    if (_path_is_absolute(path)) {
        RETURN_ERROR(_rewrite_path(did, path, new_path));
        return 0;
    }

    // for relative paths 'dirfd' needs to be resolved
    char fd_path[PATH_MAX];
    if (_fd_path_domain(did, dirfd, fd_path) == -1) {
        WARNING("FD %d not valid", dirfd);
        return -1;
    }
    const char *base_path = _domain_base_path(did);
    size_t size = strlen(base_path);

    // rel_path must have '/' at start
    assert_ifdebug(strncmp(base_path, fd_path, size) == 0);
    assert_ifdebug(size > 0);
    char *rel_path = fd_path + size - 1;
    rel_path[0] = '/';

    char full_path[PATH_MAX];
    RETURN_ERROR(_path_join_normalize(rel_path, path, full_path));
    RETURN_ERROR(_base_path_relative(did, full_path, new_path));

    PREPEND_TO_DEBUG_BUFFER("rewriting path from %s to %s\n", path, new_path);
    return 0;
}
//------------------------------------------------------------------------------



#define SYSFILTER_CHECK_FD(ti, fd) \
    if (!_fd_accessible_by_domain(ti->did, fd)) { \
        WARNING("%s: FD %d not accessible by domain %d", sysno_to_str(ti->syscall_nr), fd, ti->did); \
        SYSFILTER_RETURN(ti, -EBADF); \
    }
//------------------------------------------------------------------------------

#define SYSFILTER_REGISTER_FD(ti, fd) \
    /* let the user handle error / errno */ \
    if (fd < 0) { \
        return; \
    } \
    assert(fd < NUM_FDS); \
    /*assert_ifdebug(sf_data.fd_domain_mapping[fd] == FD_DOMAIN_NONE_OR_CLOSED || sf_data.fd_domain_mapping[fd] == ti->did);*/ \
    /*if(! (sf_data.fd_domain_mapping[fd] == FD_DOMAIN_NONE_OR_CLOSED ||sf_data.fd_domain_mapping[fd] == ti->did)){*/\
    if (!_fd_accessible_by_domain(ti->did, fd)) { \
        WARNING("%s: FD %d not accessible by domain %d", sysno_to_str(ti->syscall_nr), (int)fd, ti->did); \
    }\
    sf_data.fd_domain_mapping[fd] = ti->did; \
//------------------------------------------------------------------------------

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

#define WRAPPER_FD_RET(pos_fd) \
static void _sf_wrapper_fd_ret_fd_##pos_fd(trace_info_t *ti) { \
    DEBUG_FILTER(); \
    \
    if (IS_SYSCALL_ENTER(ti)) { \
        int fd = (int)ti->args[pos_fd]; \
        SYSFILTER_CHECK_FD(ti, fd); \
    } else { \
        SYSFILTER_REGISTER_FD(ti, ti->return_value); \
    } \
}
//------------------------------------------------------------------------------

#define WRAPPER_PATH(pos_path) \
static void _sf_wrapper_path_##pos_path(trace_info_t *ti) { \
    DEBUG_FILTER(); \
    \
    if (IS_SYSCALL_ENTER(ti)) { \
        /*SYSFILTER_RETURN_IF_ERROR(ti, sf_arg_string_copy(ti, pos_path));*/ \
        const char *pathname = (const char *)ti->args[pos_path]; \
        char *new_pathname = sf_arg_alloc_native(ti, PATH_MAX); \
        pthread_mutex_lock(&sf_localstorage.path_mutex); \
        if (_rewrite_path(ti->did, pathname, new_pathname) == -1) { \
            pthread_mutex_unlock(&sf_localstorage.path_mutex); \
            SYSFILTER_RETURN(ti, -ENAMETOOLONG); \
        } \
        ti->args[pos_path] = (long)new_pathname; \
        PREPEND_TO_DEBUG_BUFFER("new_pathname = %s\n", new_pathname); \
    } \
    else { \
        pthread_mutex_unlock(&sf_localstorage.path_mutex); \
    } \
}
//------------------------------------------------------------------------------

#define WRAPPER_FD_PATH(pos_fd, pos_path) \
static void _sf_wrapper_fd_##pos_fd##_path_##pos_path(trace_info_t *ti) { \
    DEBUG_FILTER(); \
    \
    if (IS_SYSCALL_ENTER(ti)) { \
        /*SYSFILTER_RETURN_IF_ERROR(ti, sf_arg_string_copy(ti, pos_path));*/ \
        int dirfd = (int)ti->args[pos_fd]; \
        const char *pathname = (const char *)ti->args[pos_path]; \
        SYSFILTER_CHECK_FD(ti, dirfd); \
        \
        char *new_pathname = sf_arg_alloc_native(ti, PATH_MAX); \
        pthread_mutex_lock(&sf_localstorage.path_mutex); \
        if (_rewrite_fd_with_path(ti->did, dirfd, pathname, new_pathname) == -1) { \
            pthread_mutex_unlock(&sf_localstorage.path_mutex); \
            SYSFILTER_RETURN(ti, -ENAMETOOLONG); \
        } \
        ti->args[pos_path] = (long)new_pathname; \
        PREPEND_TO_DEBUG_BUFFER("new_pathname = %s\n", new_pathname); \
    } \
    else { \
        pthread_mutex_unlock(&sf_localstorage.path_mutex); \
    } \
}
//------------------------------------------------------------------------------

#define WRAPPER_FD_RET_PATH(pos_path) \
static void _sf_wrapper_fd_ret_path_##pos_path(trace_info_t *ti) { \
    DEBUG_FILTER(); \
    \
    if (IS_SYSCALL_ENTER(ti)) { \
        /*SYSFILTER_RETURN_IF_ERROR(ti, sf_arg_string_copy(ti, pos_path));*/ \
        const char *pathname = (const char *)ti->args[pos_path]; \
        char *new_pathname = sf_arg_alloc_native(ti, PATH_MAX); \
        pthread_mutex_lock(&sf_localstorage.path_mutex); \
        if (_rewrite_path(ti->did, pathname, new_pathname) == -1) { \
            pthread_mutex_unlock(&sf_localstorage.path_mutex); \
            SYSFILTER_RETURN(ti, -ENAMETOOLONG); \
        } \
        ti->args[pos_path] = (long)new_pathname; \
        PREPEND_TO_DEBUG_BUFFER("new_pathname = %s\n", new_pathname); \
    } \
    else { \
        pthread_mutex_unlock(&sf_localstorage.path_mutex); \
        SYSFILTER_REGISTER_FD(ti, ti->return_value); \
    } \
}
//------------------------------------------------------------------------------

#define WRAPPER_FD_RET_FD_PATH(pos_fd, pos_path) \
static void _sf_wrapper_fd_ret_fd_##pos_fd##_path_##pos_path(trace_info_t *ti) { \
    DEBUG_FILTER(); \
    \
    if (IS_SYSCALL_ENTER(ti)) { \
        /*SYSFILTER_RETURN_IF_ERROR(ti, sf_arg_string_copy(ti, pos_path));*/ \
        int dirfd = (int)ti->args[pos_fd]; \
        const char *pathname = (const char *)ti->args[pos_path]; \
        SYSFILTER_CHECK_FD(ti, dirfd); \
        \
        char *new_pathname = sf_arg_alloc_native(ti, PATH_MAX); \
        pthread_mutex_lock(&sf_localstorage.path_mutex); \
        if (_rewrite_fd_with_path(ti->did, dirfd, pathname, new_pathname) == -1) { \
            pthread_mutex_unlock(&sf_localstorage.path_mutex); \
            SYSFILTER_RETURN(ti, -ENAMETOOLONG); \
        } \
        ti->args[pos_path] = (long)new_pathname; \
        PREPEND_TO_DEBUG_BUFFER("new_pathname = %s\n", new_pathname); \
    } \
    else { \
        pthread_mutex_unlock(&sf_localstorage.path_mutex); \
        SYSFILTER_REGISTER_FD(ti, ti->return_value); \
    } \
}
//------------------------------------------------------------------------------

// e.g. int eventfd(unsigned int initval, int flags);
static void _sf_wrapper_fd_ret(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (!IS_SYSCALL_ENTER(ti)) {
        SYSFILTER_REGISTER_FD(ti, ti->return_value);
    }
}

// int close(int fd);
static void _sf_sys_close(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (IS_SYSCALL_ENTER(ti)) {
        int fd = (int)ti->args[0];
        SYSFILTER_CHECK_FD(ti, fd);

        // allow closing std filedescriptors
        //~if (fd <= STDERR_FILENO) {
        //~    WARNING("close: cannot close fd <= STDERR");
        //~    SYSFILTER_RETURN(ti, -EBADF);
        //~}
    }else{
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
        SYSFILTER_REGISTER_FD(ti, ti->return_value);
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
        // also potentially closes newfd
        // however, it cannot change domain
        SYSFILTER_CHECK_FD(ti, newfd);
    }
    else {
        SYSFILTER_REGISTER_FD(ti, ti->return_value);
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
        SYSFILTER_REGISTER_FD(ti, ti->return_value);
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

            SYSFILTER_REGISTER_FD(ti, fildes[0]);
            SYSFILTER_REGISTER_FD(ti, fildes[1]);
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

        SYSFILTER_REGISTER_FD(ti, sv[0]);
        SYSFILTER_REGISTER_FD(ti, sv[1]);

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

// int renameat(int oldfd, const char *old, int newfd, const char *new);
static void _sf_sys_renameat(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (IS_SYSCALL_ENTER(ti)) {
        /*SYSFILTER_RETURN_IF_ERROR(ti, sf_arg_string_copy(ti, 1));
        SYSFILTER_RETURN_IF_ERROR(ti, sf_arg_string_copy(ti, 3));*/

        int oldfd = (int)ti->args[0];
        int newfd = (int)ti->args[1];
        const char *old = (const char *)ti->args[1];
        const char *new = (const char *)ti->args[3];
        SYSFILTER_CHECK_FD(ti, oldfd);
        SYSFILTER_CHECK_FD(ti, newfd);

        char *old_rewritten = sf_arg_alloc_native(ti, PATH_MAX);
        pthread_mutex_lock(&sf_localstorage.path_mutex);
        if (_rewrite_fd_with_path(ti->did, oldfd, old, old_rewritten) == -1) {
            SYSFILTER_RETURN(ti, -ENAMETOOLONG);
            pthread_mutex_unlock(&sf_localstorage.path_mutex);
        }
        ti->args[1] = (long)old_rewritten;
        char *new_rewritten = sf_arg_alloc_native(ti, PATH_MAX);
        if (_rewrite_fd_with_path(ti->did, newfd, new, new_rewritten) == -1) {
            SYSFILTER_RETURN(ti, -ENAMETOOLONG);
            pthread_mutex_unlock(&sf_localstorage.path_mutex);
        }
        ti->args[3] = (long)new_rewritten;
        PREPEND_TO_DEBUG_BUFFER("rename(%s, %s)\n", old_rewritten, new_rewritten);
    }
    else {
        pthread_mutex_unlock(&sf_localstorage.path_mutex);
    }
}
//------------------------------------------------------------------------------

// int rename(const char *oldpath, const char *newpath);
static void _sf_sys_rename(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (IS_SYSCALL_ENTER(ti)) {
        /*SYSFILTER_RETURN_IF_ERROR(ti, sf_arg_string_copy(ti, 0));
        SYSFILTER_RETURN_IF_ERROR(ti, sf_arg_string_copy(ti, 1));*/

        const char *old = (const char *)ti->args[0];
        const char *new = (const char *)ti->args[1];

        pthread_mutex_lock(&sf_localstorage.path_mutex);
        char *old_rewritten = sf_arg_alloc_native(ti, PATH_MAX);
        if (_rewrite_path(ti->did, old, old_rewritten) == -1) {
            SYSFILTER_RETURN(ti, -ENAMETOOLONG);
            pthread_mutex_unlock(&sf_localstorage.path_mutex);
        }
        ti->args[0] = (long)old_rewritten;
        char *new_rewritten = sf_arg_alloc_native(ti, PATH_MAX);
        if (_rewrite_path(ti->did, new, new_rewritten) == -1) {
            SYSFILTER_RETURN(ti, -ENAMETOOLONG);
            pthread_mutex_unlock(&sf_localstorage.path_mutex);
        }
        ti->args[1] = (long)new_rewritten;
        PREPEND_TO_DEBUG_BUFFER("rename(%s, %s)\n", old_rewritten, new_rewritten);
    }
    else {
        pthread_mutex_unlock(&sf_localstorage.path_mutex);
    }
}

// char *getcwd(char *buf, size_t size);
// WARNING: getcwd(...) != syscall(SYS_getcwd, ...)
static void _sf_sys_getcwd(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (IS_SYSCALL_ENTER(ti)) {
        char *buf = (char *)ti->args[0];
        size_t size = (size_t)ti->args[1];

        pthread_mutex_lock(&sf_localstorage.path_mutex);
        const char *cwd = _domain_rel_cwd(ti->did);
        size_t cwd_size = strlen(cwd) + 1;

        if (size < cwd_size) {
            pthread_mutex_unlock(&sf_localstorage.path_mutex);
            SYSFILTER_RETURN(ti, -ERANGE);
        }
        pk_memcpy(buf, cwd, cwd_size);
        pthread_mutex_unlock(&sf_localstorage.path_mutex);

        SYSFILTER_RETURN(ti, (long)cwd_size - 1);
    }
}

// int chdir(const char *path);
static void _sf_sys_chdir(trace_info_t *ti)
{
    DEBUG_FILTER();

    if (IS_SYSCALL_ENTER(ti)) {
        /*SYSFILTER_RETURN_IF_ERROR(ti, sf_arg_string_copy(ti, 0));*/

        long ret = 0;
        const char *path = (char *)ti->args[0];
        if (strlen(path) + 1 > PATH_MAX) {
            WARNING("path to new cwd is too long");
            SYSFILTER_RETURN(ti, -ENAMETOOLONG);
        }

        pthread_mutex_lock(&sf_localstorage.path_mutex);
        char *old_cwd = _domain_rel_cwd(ti->did);
        const char *new_cwd = path;

        // if the path to the new cwd is relative, join it with the old one
        char new_cwd1[PATH_MAX];
        if (_path_is_relative(path)) {
            if (_path_join_normalize(old_cwd, path, new_cwd1) != 0) {
                WARNING("path to new cwd is too long");
                pthread_mutex_unlock(&sf_localstorage.path_mutex);
                SYSFILTER_RETURN(ti, -ENAMETOOLONG);
            }
            new_cwd = new_cwd1;
        }

        // check if folder is actually there
        char new_cwd_full[PATH_MAX];
        if (_base_path_relative(ti->did, new_cwd, new_cwd_full) != 0) {
            WARNING("path to new cwd is too longgg");
            pthread_mutex_unlock(&sf_localstorage.path_mutex);
            SYSFILTER_RETURN(ti, -ENAMETOOLONG);
        }

        struct stat s;
        if (stat(new_cwd_full, &s) != 0) {
            WARNING("cannot access new cwd");
            pthread_mutex_unlock(&sf_localstorage.path_mutex);
            SYSFILTER_RETURN(ti, -errno);
        }

        if (!S_ISDIR(s.st_mode)) {
            WARNING("new chdir is not a directory");
            pthread_mutex_unlock(&sf_localstorage.path_mutex);
            SYSFILTER_RETURN(ti, -ENOENT);
        }

        size_t new_cwd_size = strlen(new_cwd) + 1;
        pk_memcpy(old_cwd, new_cwd, new_cwd_size);
        pthread_mutex_unlock(&sf_localstorage.path_mutex);

        SYSFILTER_RETURN(ti, 0);
    }
}
//------------------------------------------------------------------------------

// int fcntl(int fildes, int cmd, ...)
static void _sf_sys_fcntl(trace_info_t *ti)
{
    DEBUG_FILTER();

    int fildes = (int)ti->args[0];
    int cmd = (int)ti->args[1];

    if (IS_SYSCALL_ENTER(ti)) {
        SYSFILTER_CHECK_FD(ti, fildes);
    }
    else {
        if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
            SYSFILTER_REGISTER_FD(ti, ti->return_value);
        }
    }
}
//------------------------------------------------------------------------------

static void PK_CODE _sf_sys_mmap(trace_info_t *ti)
{
    DEBUG_FILTER();
    
    // check fd before executing the API call
    int fd = (int)ti->args[4];
    SYSFILTER_CHECK_FD(ti, fd);

    void *ret = pk_mmap2(ti->did, (void *)ti->args[0], (size_t)ti->args[1], (int)ti->args[2], (int)ti->args[3], fd, (off_t)ti->args[5]);
    if ((long)ret == -1) {
        SYSFILTER_RETURN(ti, -errno);
    } else {
        SYSFILTER_RETURN(ti, (long)ret);
    }
}
//------------------------------------------------------------------------------

WRAPPER_FD(0)                   // e.g. ssize_t write(int fd, const void *buf, size_t count);
WRAPPER_FD_RET(0)               //generates _sf_wrapper_fd_ret_fd_0 for FILTER_FD_RET_FD_0
WRAPPER_FD(4)                   // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
WRAPPER_PATH(0)                 // e.g. int mkdir(const char *pathname, mode_t mode);
WRAPPER_FD_PATH(0, 1)           // e.g. int mkdirat(int dirfd, const char *pathname, mode_t mode);
WRAPPER_FD_RET_PATH(0)          // e.g. int open(const char *pathname, int flags);
WRAPPER_FD_RET_FD_PATH(0, 1)    // e.g. int openat(int dirfd, const char *pathname, int flags);

#define ARG_COPY_PIPE        {{ARG_TYPE_ALLOC_RESTORE, 2 * sizeof(int)}}
#define ARG_COPY_SOCKET_PAIR {{0}, {0}, {0}, {ARG_TYPE_ALLOC_RESTORE, 2 * sizeof(int)}}
#define ARG_COPY_GETCWD      {{ARG_TYPE_ALLOC_RESTORE_ARGLEN, 1}} // length of arg 0 is in arg 1

#define FILTER_FD_0                     _sf_wrapper_fd_0,               {{0}}
#define FILTER_FD_4                     _sf_wrapper_fd_4,               {{0}}
#define FILTER_FD_RET                   _sf_wrapper_fd_ret,             {{0}}
#define FILTER_FD_RET_FD_0              _sf_wrapper_fd_ret_fd_0,        {{0}}
#define FILTER_PATH_0                   _sf_wrapper_path_0,             ARG_COPY_PATH_0
#define FILTER_FD_RET_PATH_0            _sf_wrapper_fd_ret_path_0,      ARG_COPY_PATH_0
#define FILTER_FD_0_PATH_1              _sf_wrapper_fd_0_path_1,        ARG_COPY_PATH_1
#define FITLER_FD_RET_FD_0_PATH_1       _sf_wrapper_fd_ret_fd_0_path_1, ARG_COPY_PATH_1



#define MANUAL_SYSCALL(sys_name, type) { SYS_##sys_name, _sf_wrapper_##type, ARG_COPY_##type }

static sys_manual_t syscalls_extended[] = {

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

    { SYS_rename,                _sf_sys_rename,                ARG_COPY_PATH_0_PATH_1  },

    { SYS_renameat,              _sf_sys_renameat,              ARG_COPY_PATH_1_PATH_3  },
    { SYS_renameat2,             _sf_sys_renameat,              ARG_COPY_PATH_1_PATH_3  },

    { SYS_getcwd,                _sf_sys_getcwd,                ARG_COPY_GETCWD         },
    { SYS_chdir,                 _sf_sys_chdir,                 ARG_COPY_PATH_0         },

    { SYS_socketpair,            _sf_sys_socketpair,            ARG_COPY_SOCKET_PAIR    },


    // -------------------------------------------------------
    // fd_0
    { SYS_read, FILTER_FD_0 },
    { SYS_write, FILTER_FD_0 },
    { SYS_fstat, FILTER_FD_0 },
    { SYS_lseek, FILTER_FD_0 },
    { SYS_ioctl, FILTER_FD_0 },
    { SYS_pread64, FILTER_FD_0 },
    { SYS_pwrite64, FILTER_FD_0 },
    { SYS_readv, FILTER_FD_0 },
    { SYS_writev, FILTER_FD_0 },
    { SYS_flock, FILTER_FD_0 },
    { SYS_fsync, FILTER_FD_0 },
    { SYS_fdatasync, FILTER_FD_0 },
    { SYS_ftruncate, FILTER_FD_0 },
    { SYS_getdents, FILTER_FD_0 },
    { SYS_fchdir, FILTER_FD_0 },
    { SYS_fchmod, FILTER_FD_0 },
    { SYS_fchown, FILTER_FD_0 },
    { SYS_fstatfs, FILTER_FD_0 },
    { SYS_readahead, FILTER_FD_0 },
    { SYS_fsetxattr, FILTER_FD_0 },
    { SYS_fgetxattr, FILTER_FD_0 },
    { SYS_flistxattr, FILTER_FD_0 },
    { SYS_fremovexattr, FILTER_FD_0 },
    { SYS_getdents64, FILTER_FD_0 },
    { SYS_fadvise64, FILTER_FD_0 },
    { SYS_sync_file_range, FILTER_FD_0 },
    { SYS_vmsplice, FILTER_FD_0 },
    { SYS_fallocate, FILTER_FD_0 },
    { SYS_timerfd_settime, FILTER_FD_0 },
    { SYS_timerfd_gettime, FILTER_FD_0 },
    { SYS_preadv, FILTER_FD_0 },
    { SYS_pwritev, FILTER_FD_0 },
    { SYS_syncfs, FILTER_FD_0 },
    { SYS_setns, FILTER_FD_0 },
    { SYS_finit_module, FILTER_FD_0 },
    { SYS_preadv2, FILTER_FD_0 },
    { SYS_pwritev2, FILTER_FD_0 },

    // -------------------------------------------------------
    // network fd_0
    { SYS_connect, FILTER_FD_0 },
    { SYS_accept, FILTER_FD_RET_FD_0 },
    { SYS_accept4, FILTER_FD_RET_FD_0 },
    { SYS_sendto, FILTER_FD_0 },
    { SYS_recvfrom, FILTER_FD_0 },
    { SYS_sendmsg, FILTER_FD_0 },
    { SYS_recvmsg, FILTER_FD_0 },
    { SYS_shutdown, FILTER_FD_0 },
    { SYS_bind, FILTER_FD_0 },
    { SYS_listen, FILTER_FD_0 },
    { SYS_getsockname, FILTER_FD_0 },
    { SYS_getpeername, FILTER_FD_0 },
    { SYS_setsockopt, FILTER_FD_0 },
    { SYS_getsockopt, FILTER_FD_0 },
    { SYS_getpmsg, FILTER_FD_0 },
    { SYS_putpmsg, FILTER_FD_0 },
    { SYS_recvmmsg, FILTER_FD_0 },
    { SYS_recvmmsg_time64, FILTER_FD_0 },
    { SYS_sendmmsg, FILTER_FD_0 },
    // -------------------------------------------------------
    // path_0
    { SYS_stat, FILTER_PATH_0 },
    { SYS_lstat, FILTER_PATH_0 },
    { SYS_access, FILTER_PATH_0 },
    { SYS_truncate, FILTER_PATH_0 },
    { SYS_mkdir, FILTER_PATH_0 },
    { SYS_rmdir, FILTER_PATH_0 },
    { SYS_unlink, FILTER_PATH_0 },
    { SYS_readlink, FILTER_PATH_0 },
    { SYS_chmod, FILTER_PATH_0 },
    { SYS_chown, FILTER_PATH_0 },
    { SYS_lchown, FILTER_PATH_0 },
    { SYS_utime, FILTER_PATH_0 },
    { SYS_mknod, FILTER_PATH_0 },
    { SYS_uselib, FILTER_PATH_0 },
    { SYS_statfs, FILTER_PATH_0 },
    { SYS_acct, FILTER_PATH_0 },
    { SYS_setxattr, FILTER_PATH_0 },
    { SYS_lsetxattr, FILTER_PATH_0 },
    { SYS_getxattr, FILTER_PATH_0 },
    { SYS_lgetxattr, FILTER_PATH_0 },
    { SYS_listxattr, FILTER_PATH_0 },
    { SYS_llistxattr, FILTER_PATH_0 },
    { SYS_removexattr, FILTER_PATH_0 },
    { SYS_lremovexattr, FILTER_PATH_0 },
    { SYS_utimes, FILTER_PATH_0 },

    // -------------------------------------------------------
    // fd_0_path_1
    { SYS_mkdirat, FILTER_FD_0_PATH_1 },
    { SYS_mknodat, FILTER_FD_0_PATH_1 },
    { SYS_fchownat, FILTER_FD_0_PATH_1 },
    { SYS_futimesat, FILTER_FD_0_PATH_1 },
    { SYS_unlinkat, FILTER_FD_0_PATH_1 },
    { SYS_readlinkat, FILTER_FD_0_PATH_1 },
    { SYS_fchmodat, FILTER_FD_0_PATH_1 },
    { SYS_faccessat, FILTER_FD_0_PATH_1 },
    { SYS_utimensat, FILTER_FD_0_PATH_1 },
    {SYS_newfstatat, FILTER_FD_0_PATH_1 },


    // -------------------------------------------------------
    // fd_ret
    { SYS_timerfd_create, FILTER_FD_RET },
    { SYS_eventfd, FILTER_FD_RET },
    { SYS_eventfd2, FILTER_FD_RET },
    { SYS_socket, FILTER_FD_RET },

    // -------------------------------------------------------
    // fd_ret_path_0
    { SYS_creat, FILTER_FD_RET_PATH_0 },
    { SYS_open, FILTER_FD_RET_PATH_0 },

    // -------------------------------------------------------
    // fd_ret_fd_0_path_1
    { SYS_openat, FITLER_FD_RET_FD_0_PATH_1 },
    { SYS_inotify_add_watch, FITLER_FD_RET_FD_0_PATH_1 },


    // dangerous operations on fds
    { SYS_fcntl,                 _sf_sys_fcntl             },
    { SYS_fcntl64,               _sf_sys_fcntl             },
    { SYS_open_by_handle_at,     SYSCALL_DENIED            },
    { SYS_name_to_handle_at,     SYSCALL_DENIED            },
    { SYS_memfd_create,          SYSCALL_DENIED            },
    { SYS_perf_event_open,       SYSCALL_DENIED            },

    // dangerous operations of paths
    { SYS_swapon,                SYSCALL_DENIED            },
    { SYS_swapoff,               SYSCALL_DENIED            },
    { SYS_quotactl,              SYSCALL_DENIED            },

    { SYS_io_uring_setup,        SYSCALL_DENIED            },
    { SYS_io_uring_enter,        SYSCALL_DENIED            },
    { SYS_io_uring_register,     SYSCALL_DENIED            },

    // notify
    { SYS_inotify_rm_watch,      SYSCALL_DENIED            },
    { SYS_fanotify_init,         SYSCALL_DENIED            },
    { SYS_fanotify_mark,         SYSCALL_DENIED            },
    { SYS_inotify_init,          SYSCALL_DENIED            },
    { SYS_inotify_init1,         SYSCALL_DENIED            },

    // message queues
    { SYS_mq_open,               SYSCALL_DENIED            },
    { SYS_mq_timedsend,          SYSCALL_DENIED            },
    { SYS_mq_timedsend_time64,   SYSCALL_DENIED            },
    { SYS_mq_timedreceive,       SYSCALL_DENIED            },
    { SYS_mq_timedreceive_time64,SYSCALL_DENIED            },
    { SYS_mq_notify,             SYSCALL_DENIED            },
    { SYS_mq_getsetattr,         SYSCALL_DENIED            },
    { SYS_mq_unlink,             SYSCALL_DENIED            },

    // strange pidfd syscalls
    { SYS_pidfd_open,            SYSCALL_DENIED            },
    { SYS_pidfd_getfd,           SYSCALL_DENIED            },
    { SYS_pidfd_send_signal,     SYSCALL_DENIED            },

    { SYS_openat2,               SYSCALL_DENIED            },

    // link related syscalls (probably not implementable with relative links)
    { SYS_link,                  SYSCALL_DENIED            },
    { SYS_symlink,               SYSCALL_DENIED            },
    { SYS_linkat,                SYSCALL_DENIED            },

    // for benchmarking
    { SYS_getpid,                _sfu_empty_filter          },
};
//------------------------------------------------------------------------------

int PK_API sf_localstorage_filters_init(int did)
{

    if (sf_localstorage._sf_localstorage_filters_initialized) {
        ERROR_FAIL("sf_localstorage_filters already initialized");
    }

    for (size_t i = 0; i < NUM_FDS; i++) {
        sf_data.fd_domain_mapping[i] = FD_DOMAIN_NONE_OR_CLOSED;
    }
    sf_data.fd_domain_mapping[STDIN_FILENO]  = FD_DOMAIN_ANY;
    sf_data.fd_domain_mapping[STDOUT_FILENO] = FD_DOMAIN_ANY;
    sf_data.fd_domain_mapping[STDERR_FILENO] = FD_DOMAIN_ANY;

    pthread_mutexattr_t attr;
    assert(pthread_mutexattr_init(&attr) == 0);
    assert(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0);
    assert(pthread_mutex_init(&sf_localstorage.path_mutex, &attr) == 0);

    assert(snprintf(sf_localstorage.localstorage_path, PATH_MAX, LOCALSTORAGE_DIR, getuid()) <= PATH_MAX);

    // create localstorage path if it does not exist
    struct stat sb;
    if (!(stat(sf_localstorage.localstorage_path, &sb) == 0 && S_ISDIR(sb.st_mode))) {
        DEBUG_SF("creating localstorage path");
        mkdir(sf_localstorage.localstorage_path, 0700);  // only current user can access this folder
    }

    for (size_t i = 0; i < sizeof(syscalls_extended) / sizeof(sys_manual_t); i++) {
        sys_manual_t *s = &syscalls_extended[i];
        if(s->sysno == SYSNO_UNDEFINED){
            continue;
        }
        if (did != -1) {
            // install filters in domain
            pk_sysfilter_domain(did, s->sysno, s->filter, s->arg_copy);
            _domain_init(did); //this is optional to avoid doing it lazily
        }
        else {
            // install filters in monitor
            pk_sysfilter_monitor(s->sysno, s->filter, s->arg_copy);
        }
    }

    sf_localstorage._sf_localstorage_filters_initialized = true;
    return 0;
}
//------------------------------------------------------------------------------
