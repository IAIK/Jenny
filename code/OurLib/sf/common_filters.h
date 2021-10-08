#pragma once

#include "sf_internal.h"
#include "pk_internal.h"
#include "syscall_defs.h"


/**
 * Path library for filters.
 * WARNING: A length of PATH_MAX is expected for all functions.
 */


//------------------------------------------------------------------------------
/**
 * @brief Checks, if @p fd is accessible by @p did. Also returns true for
 * invalid file descriptors.
 */
FORCE_INLINE bool _fd_accessible_by_domain(int did, int fd)
{
    assert_ifdebug(did >= 0);

    if(!sf_data.sf_filters_initialized){
        return true;
    }

    if (fd < 0) {
        return true;
    }

    if (fd >= NUM_FDS) {
        return false;
    }

    int mapping = sf_data.fd_domain_mapping[fd];

    if (mapping == DID_FOR_EXCEPTION_HANDLER /*did_for_exception_handler*/){
        return false;
    }

    if(sf_data.sf_filter_current == SF_EXTENDED_MONITOR ||
       sf_data.sf_filter_current == SF_EXTENDED_DOMAIN)
    {
        if (mapping == FD_DOMAIN_ANY || mapping == did || mapping == FD_DOMAIN_NONE_OR_CLOSED) {
            return true;
        }
        return false;
    }

    return true;
}
//------------------------------------------------------------------------------


/**
 * @brief Resolves path of file descriptor.
 *
 * Reads the link /proc/self/fd/{fd} to resolve the path
 * a file descriptor currently points to. Removes ' (deleted)'
 * from the path, if a file is actually deleted.
 *
 * @param fd
 *        file descriptor to be resolved
 * @param path
 *        resolved path
 * @param is_deleted
 *        if not NULL, pointer to int which states if was was deleted or not
 * @return
 *        0 on sucess, or -1 on error (link cannot be resolved, is too long)
 *
 */
FORCE_INLINE int _fd_path2(int fd, char *path, int* is_deleted)
{
    char proc_path[30];
    assert(snprintf(proc_path, 30, "/proc/self/fd/%d", fd) < 30);

    int len = readlink(proc_path, path, PATH_MAX);
    assert(len < PATH_MAX);
    if (len < 0 || len >= PATH_MAX) {
        return -1;
    }
    path[len] = '\0';

    // remove ' deleted' from path as we do not care
    static const char *deleted_str = " (deleted)";
    size_t deleted_len = strlen(deleted_str);
    char *path1 = path + len - deleted_len;

    if(is_deleted){
        *is_deleted = 0;
    }

    if (len < deleted_len) {
        return 0;
    }

    // fast check (a file can just be named ' (deleted)')
    if (strcmp(path1, deleted_str) == 0) {
        // slow check (to be sure)
        if (access(path, F_OK) != 0) {
            // remove ' (deleted)'
            path1[0] = '\0';
            if(is_deleted){
                *is_deleted = 1;
            }
        }
    }
    return 0;
}
FORCE_INLINE int _fd_path(int fd, char *path)
{
    return _fd_path2(fd, path, NULL);
}
//------------------------------------------------------------------------------

/**
 * @brief Returns true, if the @p path is absolute.
 */
FORCE_INLINE bool _path_is_absolute(const char *path)
{
    return path[0] == '/';
}

/**
 * @brief Returns true, if the @p path is relative.
 */
FORCE_INLINE bool _path_is_relative(const char *path)
{
    return path[0] != '/';
}

/**
 * @brief Returns the location of the next component in the path.
 *
 * Starting from @p last, search for the next string between two '/'.
 * Return the location by specifying @p start and @p end point.
 *
 * @param path
 *        Path string.
 * @param last
 *        Location of @p end at last invocation of function.
 *        Set to @p path at beginning.
 * @param start
 *        Starting position of the path component is placed here.
 * @param end
 *        End position of the path component is placed here.
 * @return
 *        0 if there are more path components.
 *       -1 if the last component is reached.
 */
FORCE_INLINE int _path_next_component(const char *path, const char *last, const char **start, const char **end)
{
    for (; *last == '/' && *last != '\0'; ++last);
    *start = last;
    const char *curr = *start;
    for (; *curr != '/' && *curr != '\0'; ++curr);
    *end = curr;
    if (*start == *end) {
        return -1;
    }
    return 0;
}

/**
 * @brief Returns the location of the previous component in the path.
 *
 * Starting from @p last, search for the previous string between two '/'.
 * Return the location by specifying @p start and @p end point.
 *
 * @param path
 *        Path string.
 * @param last
 *        Location of @p start at last invocation of function.
 *        Set to @p path + strlen(@p path) at beginning.
 * @param start
 *        Starting position of the path component is placed here.
 * @param end
 *        End position of the path component is placed here.
 * @return
 *        0 if there are more path components.
 *       -1 if the last component is reached.
 */
FORCE_INLINE int _path_prev_component(const char *path, const char *last, const char **start, const char **end)
{
    --last;
    for (; last != path - 1 && *last == '/'; --last);
    *end = last + 1;
    const char *curr = last;
    for (; curr != path - 1 && *curr != '/'; --curr);
    *start = curr + 1;

    if (*end == path) {
        return -1;
    }
    return 0;
}

/**
 * @brief Returns true, if the path component is a '..'.
 */
FORCE_INLINE bool _path_component_is_back(const char *start, const char *end) {
    if (end - start != 2) {
        return false;
    }
    return memcmp(start, "..", 2) == 0;
}

/**
 * @brief Returns true, if the path component is a '.'.
 */
FORCE_INLINE bool _path_component_is_current(const char *start, const char *end) {
    if (end - start != 1) {
        return false;
    }
    return memcmp(start, ".", 1) == 0;
}

/**
 * @brief Normalizes specifed path.
 *
 * Removes all redundant '.' and '/'. Removes path components according to '..'.
 *
 * @param path
 *        Path string.
 * @param new_path
 *        Normalized path is placed here.
 */
FORCE_INLINE void _path_normalize(const char *path, char *new_path)
{
    bool is_relative = _path_is_relative(path);
    const char *start = path + strlen(path), *end;

    char *dst = new_path + PATH_MAX - 1;
    *dst = '\0';
    int skip = 0;
    for (int i = 0; _path_prev_component(path, start, &start, &end) == 0; i++) {
        if (_path_component_is_back(start, end)) {
            // count the number of ".."
            ++skip;
            continue;
        }
        else if (_path_component_is_current(start, end)) {
            // skip all "."
            continue;
        }

        // skip component according to previous ".."
        if (skip > 0) {
            --skip;
            continue;
        }

        size_t component_size = end - start;
        dst -= (component_size + 1);
        assert(dst >= new_path);

        pk_memcpy(dst + 1, start, component_size);
        *dst = '/';
    }

    // conditions for beginning of absolute and relative paths

    size_t new_path_size = new_path + PATH_MAX - dst;
    // if path is relative, leave ".." at front
    if (is_relative) {
        for (; skip > 0; --skip) {
            dst -= 3;

            assert(dst >= new_path);
            pk_memcpy(dst, "/..", 3);
        }

        // re-calculate
        new_path_size = new_path + PATH_MAX - dst;
        if (new_path_size == 1) {
            // empty relative path -> "."
            *(--dst) = '.';
            ++new_path_size;
        }
        else {
            // non-empty relative path -> remove "/"
            ++dst;
            --new_path_size;
        }
    }
    else {
        if (new_path_size == 1) {
            // empty absolute path -> "/"
            *(--dst) = '/';
            ++new_path_size;
        }
    }

    // move to beginning of new_path
    memmove(new_path, dst, new_path_size);
}

/**
 * @brief Joins paths.
 *
 * Joins @p path1 and @p path2 without normalizing them.
 *
 * @param path1
 *        First path.
 * @param path2
 *        Second path.
 * @param new_path
 *        Joined path is placed here.
 * @return
 *        0 on success, -1 on error (path too long)
 */
FORCE_INLINE int _path_join(const char *path1, const char *path2, char *new_path)
{
    size_t l1 = strlen(path1);
    size_t l2 = strlen(path2);
    bool extra_length = false;

    if (path1[l1 - 1] != '/' && path2[0] != '/') {
        extra_length = 1;
    }
    size_t joined_size = l1 + extra_length + l2 + 1;

    if (joined_size > PATH_MAX) {
        return -1;                  // final path to big for buffer
    }

    pk_memcpy(new_path, path1, l1);
    if (extra_length) {
        new_path[l1] = '/';
    }
    pk_memcpy(new_path + l1 + extra_length, path2, l2 + 1);
    return 0;
}

/**
 * @brief Joins paths and normalizes the joined path.
 *
 * Joins @p path1 and @p path2. Normalizes joined path with @a _path_normalize.
 *
 * @param path1
 *        First path.
 * @param path2
 *        Second path.
 * @param new_path
 *        Joined path is placed here.
 * @return
 *        0 on success, -1 on error (path too long)
 */
FORCE_INLINE int _path_join_normalize(const char *path1, const char *path2, char *new_path)
{
    char joined[PATH_MAX];
    if (_path_join(path1, path2, joined) == -1) {
        return -1;
    }

    _path_normalize(joined, new_path);
    return 0;
}

//------------------------------------------------------------------------------

#define CORE_FILE "core"

void PK_CODE _sf_base_filters_sanitization_init();
void PK_CODE _sf_base_filters_open_init();
void PK_CODE _sf_base_filters_prctl_init();

void PK_CODE _sf_empty_filter(trace_info_t *ti);
void PK_CODE _sfu_empty_filter(trace_info_t *ti);

/**
 *
 * Decides, if path is not dangerous for Donky.
 *
 * Returns false if path translates to
 * /proc/[any pid]/mem
 * /proc/[any pid]/stack
 *
 * /proc/[any pid]/tasks/[any tid]/mem
 * /proc/[any pid]/tasks/[any tid]/stack
 *
 * else returns true
 *
 * Why [any pid]? For some filter methods "self" resolves to the tracee pid
 * (indirect, usermode), for others to the tracer pid (user_seccomp, ptrace, ptrace_seccomp).
 * When resolving fds, the results also vary.
 *
 */
FORCE_INLINE bool _fast_prefix_match(const char* prefix, const char* target) {
    PREPEND_TO_DEBUG_BUFFER("prefix-match: %s=%s\n", prefix, target);
    while(*prefix != '\0') {
        if (unlikely(*prefix++ != *target++)) {
            return false;
        }
    }
    PREPEND_TO_DEBUG_BUFFER("match found\n");
    return true;
}

FORCE_INLINE bool _fast_postfix_match(const char* postfix, const char* target) {
    PREPEND_TO_DEBUG_BUFFER("_fast_postfix_match: %s=%s\n", postfix, target);
    size_t postfixlen = strlen(postfix);
    size_t targetlen = strlen(target);
    if (unlikely(targetlen < postfixlen)) {
        return false;
    }
    return _fast_prefix_match(target + targetlen - postfixlen, postfix);
}

FORCE_INLINE int _fd_path_monitor(int fd, char *path)
{
    if (fd == AT_FDCWD) {
        assert(getcwd(path, PATH_MAX) != NULL);
        return 0;
    }

    return _fd_path(fd, path);
}

FORCE_INLINE int _sanitize_path(trace_info_t *ti, const char *path)
{
    char absolute_path[PATH_MAX];
    if (unlikely(realpath(path, absolute_path) == NULL)) {
        if (errno != ENOENT) {
            return -errno;
        }
    }
    PREPEND_TO_DEBUG_BUFFER("sanitizing %s\n", absolute_path);

    char *curr = absolute_path;
    // path starts with "/proc/"
    if (unlikely(_fast_prefix_match("/proc/", curr))) {
        curr += strlen("/proc/");
    } else if (unlikely(_fast_postfix_match("/" CORE_FILE, curr))) {
        PREPEND_TO_DEBUG_BUFFER("Denying access to core file\n");
        return -EACCES;
    } else {
        // something outside "/proc"

        //check domain-private files
        for (size_t i = 0; i < NUM_PRIVATE_FILES; i++) {
            //PREPEND_TO_DEBUG_BUFFER("checking private_files[i] = '%s'.\n", pk_data.private_files[i].path);
            if(pk_data.private_files[i].path == NULL){
                break;
            }
            if(ti->did != pk_data.private_files[i].domain){
                if (unlikely(_fast_postfix_match(pk_data.private_files[i].path, curr))) {
                    PREPEND_TO_DEBUG_BUFFER("Denying access to file '%s' which belongs to domain %d.\n", pk_data.private_files[i].path, pk_data.private_files[i].domain);
                    return -EACCES;
                }
            }
        }

        PREPEND_TO_DEBUG_BUFFER("Allowing access outside of /proc\n");
        return 0;
    }

    /*
     * path continues with any pid
     * (for other pids these paths are not readable anyways)
     * Problem: For some filter methods "self" resolves to the tracee pid (indirect, usermode),
     * for others to the tracer pid (user_seccomp, ptrace, ptrace_seccomp).
     * When resolving fds, the results also vary.
    */
    bool procpid = false;
    while (*curr >= '0' && *curr <= '9') {
        ++curr;
        procpid = true;
    }

    if (procpid) {
        // Path is in "/proc/<pid>"
        if (_fast_prefix_match("/task", curr)) {
            curr += strlen("/task");
            if (*curr == '\0') {
                // path is /proc/<pid>/task
                return 0;
            }
            if (*curr == '/') {
                ++curr;
            }

            // path continues with any task id (thread id)
            while (*curr >= '0' && *curr <= '9') {
                ++curr;
            }
        }

        // allow
        if (*curr == '\0' ||
            strcmp("/comm", curr) == 0 ||       // allow setting thread name
            strcmp("/cmdline", curr) == 0 ||    // allow reading cmdline (is passed to main stack anyways)
            strcmp("/environ", curr) == 0 ||    // allow reading environment (is passed to main stack anyways)
            strcmp("/exe", curr) == 0 ||        // allow reading original executable file
            strcmp("/maps", curr) == 0          // allow reading memory maps
            ) {
            PREPEND_TO_DEBUG_BUFFER("Allowing access inside of /proc/self\n");
            return 0;
        }
        else {
            PREPEND_TO_DEBUG_BUFFER("Denying access inside of /proc/self\n");
            return -EACCES;
        }
    } else {
        PREPEND_TO_DEBUG_BUFFER("Allowing access inside of /proc/\n");
        // /proc outside pid
        return 0;
    }
}

FORCE_INLINE int _sanitize_fd_path(trace_info_t *ti, int fd, const char *path)
{
    assert_ifdebug(path);
    if (_path_is_absolute(path)) {
        return _sanitize_path(ti, path);
    }

    char full_path[PATH_MAX];
    if (_fd_path_monitor(fd, full_path) == -1) {
        WARNING("FD %d not valid", fd);
        return -EBADF;
    }

    if (_path_join(full_path, path, full_path) == -1) {
        WARNING("Path too long");
        return -ENAMETOOLONG;
    }

    return _sanitize_path(ti, full_path);
}

//------------------------------------------------------------------------------

FORCE_INLINE void _check_core_pattern()
{
    char core_buf[10] = {0,};
    int core_pattern = open("/proc/sys/kernel/core_pattern", O_RDONLY);
    if (-1 == core_pattern ||
        -1 == read(core_pattern, core_buf, sizeof(core_buf)) ||
        strcmp(core_buf, CORE_FILE "\n") != 0) {
        WARNING("Core pattern does not match. Sandbox could generate and read core dump files");
        WARNING("core_pattern: %s, expected %s", core_buf, CORE_FILE);
        WARNING("Please execute");
        WARNING("    echo core | sudo tee /proc/sys/kernel/core_pattern");
        // We cannot easily support other core patterns since they support wild-characters, etc.
        // Uncomment to enforce pattern "core"
        //assert(0);
    }
    close(core_pattern);
}
//------------------------------------------------------------------------------

FORCE_INLINE void _apply_custom_filters(sys_manual_t syscalls_manual[], size_t count/*, bool wrap_instead_of_overwrite*/)
{
    // Apply custom filters
    for (size_t i = 0; i < count; i++) {
        long sysno = syscalls_manual[i].sysno;
        if(sysno == SYSNO_UNDEFINED){
            continue;
        }
        assert(sysno >= 0 && sysno < NUM_MONITOR_FILTERS);
        sysent_t * monitor_filter = &sf_table[sysno];
        monitor_filter->filter = (filter_t)syscalls_manual[i].filter;
        pk_memcpy(monitor_filter->arg_copy, syscalls_manual[i].arg_copy, sizeof(syscalls_manual[i].arg_copy));
        switch ((uintptr_t)monitor_filter->filter) {
            case (uintptr_t)SYSCALL_ALLOWED:
                DEBUG_SF("Selfprotect: Custom allow syscall %3ld '%s'", sysno, sysno_to_str(sysno));
                break;
            case (uintptr_t)SYSCALL_DENIED:
                DEBUG_SF("Selfprotect: Custom deny syscall %3ld '%s'", sysno, sysno_to_str(sysno));
                break;
            default:
                DEBUG_SF("Selfprotect: Custom emulate syscall %3ld '%s'", sysno, sysno_to_str(sysno));
                break;
        }
    }
}
//------------------------------------------------------------------------------

