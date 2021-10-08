#define _GNU_SOURCE 1

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include "test7_ecall.h"
#include "test2_ecall.h"
#include "pk.h"
#include "sf.h"
#include "pk_internal.h"
#include "syscall_defs.h"


#define LENGTH(array) (sizeof(array) / sizeof(array[0]))

typedef struct {
    char* dirpath;
    char* filepath;
} relpath_t;

//--------------------------------------------------------------------
// custom domain filters for test7_nested
//--------------------------------------------------------------------
void test7_getuid_filter(trace_info_t *ti) {
    DEBUG_FILTER();
    assert_ifdebug(ti->syscall_nr == SYS_getuid);
    SYSFILTER_RETURN(ti, 0x12345678);
}

void test7_test_return_value_filter(trace_info_t *ti) {
    DEBUG_FILTER();
    assert_ifdebug(ti->syscall_nr == SYS_test_return_value);
    if (!IS_SYSCALL_ENTER(ti)) {
      ti->return_value &= 0x0000FFFF; // strip away one C0FE
    }
}

bool test_path_accessible(char *path)
{
#ifdef __x86_64__
    int fd = syscall(SYS_open, (long)path, O_RDONLY);
    if (fd > 0) close(fd);
#endif

    int fd1 = syscall(SYS_openat, AT_FDCWD, (long)path, O_RDONLY);
    if (fd1 > 0) close(fd1);

#ifdef __x86_64__
    assert((fd > 0) == (fd1 > 0));
#endif
    return fd1 > 0;
}

bool test_fd_path_accessible(int dirfd, char *path)
{
    int fd = syscall(SYS_openat, dirfd, (long)path, O_RDONLY);
    if (fd > 0) close(fd);

    return fd > 0;
}

void test7_path_sanitization()
{
    // commented out paths would not work in SF_SELF_PRCTL/SF_SELF_DONKY
    char *paths_allowed[] = {
        "/",
        "/proc",
        "/proc/self/comm",
        "/proc/self/cmdline",
        //"/proc/self/environ",
        "/proc/self/exe",
        "/proc/self/maps",
        "/proc/self/task",
    };

    char *paths_denied[] = {
        //"/proc/self/arch_status",
        //"/proc/self/fd",
        "/proc/self/mem",
        "/proc/self/stack",
        "/proc/self/syscall",
        //"/proc/self/status",
    };

    relpath_t atpaths_allowed[] = {
        { "/", "." },
        { "/", "proc" },
        { "/", "../../proc/self/comm"  },
        { "/proc", "self/cmdline" },
        //{ "/proc/self/task", "../environ" },
        { "/proc/self", "exe" },
        { "/", "proc/self/maps" },
        { "/proc/self/task", "." }
    };

    relpath_t atpaths_denied[] = {
        //{"/proc/self", "arch_status"},
        //{"/proc/self/task/..", "arch_status"},
        //{"/proc", "self/fd"},
        {"/proc", "self/mem"},
        {"/proc/self", "mem"},
        {"/proc//self", "mem"},
        {"/proc/./self", "./mem"},
        {"/proc/self/../self", "mem"},
        {"/proc/self/task/..", "mem"},
        {"/proc/self/root", "proc/self/mem"},
        {"/proc", "self/stack"},
        {"/proc/self", "stack"},
        {"/proc//self", "stack"},
        {"/proc/./self", "./stack"},
        {"/proc/self/../self", "stack"},
        {"/proc/self/task/..", "stack"},
        {"/proc/self/root", "proc/self/stack"},
    };

    for (int i = 0; i < LENGTH(paths_allowed); i++) {
        printf("Trying to access allowed path: %s\n", paths_allowed[i]);
        assert(test_path_accessible(paths_allowed[i]) == true);
    }

    for (int i = 0; i < LENGTH(paths_denied); i++) {
        printf("Trying to access denied path: %s\n", paths_denied[i]);
        assert(test_path_accessible(paths_denied[i]) == false);
        printf("errno: %d\n", errno);
        assert(errno == EACCES);
    }

    for (int i = 0; i < LENGTH(atpaths_allowed); i++) {
        char *dirpath = atpaths_allowed[i].dirpath;
        char *filepath = atpaths_allowed[i].filepath;
        printf("Trying to access allowed atpath: dir=%s file=%s\n", dirpath, filepath);
        int fd = open(dirpath, O_RDONLY);
        assert(fd > 0);
        assert(test_fd_path_accessible(fd, filepath) == true);
        assert(close(fd) == 0);
    }

    for (int i = 0; i < LENGTH(atpaths_denied); i++) {
        char *dirpath = atpaths_denied[i].dirpath;
        char *filepath = atpaths_denied[i].filepath;
        printf("Trying to access denied atpath: dir=%s file=%s\n", dirpath, filepath);
        int fd = open(dirpath, O_RDONLY);
        assert(fd > 0);
        assert(test_fd_path_accessible(fd, filepath) == false);
        assert(errno == EACCES);
        assert(close(fd) == 0);
    }

    // testing /proc/<pid>/task/<pid>
    char path[PATH_MAX];
    pid_t pid = getpid();
    sprintf(path, "/proc/%d/task/%d/cmdline", pid, pid);
    printf("Trying to access allowed path %s\n", path);
    assert(test_path_accessible(path) == true);
    sprintf(path, "/proc/%d/task/%d/mem", pid, pid);
    printf("Trying to access denied path %s\n", path);
    assert(test_path_accessible(path) == false);
    assert(errno == EACCES);

    // cannot create hardlink or move sensitive procfs files
#ifdef __x86_64__
    assert(syscall(SYS_rename, (long)"/proc/self/mem", (long)"mem.txt") == -1);
    assert(errno == EXDEV);

    assert(syscall(SYS_link, (long)"/proc/self/mem", (long)"mem.txt") == -1);
    assert(errno == EXDEV);
#endif

    assert(renameat(AT_FDCWD, "/proc/self/mem", AT_FDCWD, "mem.txt") == -1);
    assert(errno == EXDEV);

    assert(linkat(AT_FDCWD, "/proc/self/mem", AT_FDCWD, "mem.txt", 0) == -1);
    assert(errno == EXDEV);
}

void test7_monitor_filters(int *protected)
{
    //--------------------------------------------------------------------
    // testing getuid without filter
    //--------------------------------------------------------------------
    printf("testing getuid: ");
    uid_t myuid = getuid();
    printf("ret=%d\n", myuid);
    assert(0x12345678 != myuid);

    //--------------------------------------------------------------------
    // testing test_return_value with monitor filter
    //--------------------------------------------------------------------
    printf("testing return value of filtered syscalls: ");
    unsigned long val = (unsigned long)syscall(SYS_test_return_value);
    printf("ret=0x%lx\n", val);
    assert(0xC0FEC0FE == val);

    //--------------------------------------------------------------------
    // testing pk_domain_can_access_memory_syscall inside monitor filter for SYS_test_arg_copying
    //--------------------------------------------------------------------
    printf("testing pk_domain_can_access_memory in filter\n");
    assert(syscall(SYS_test_arg_copying) == 0xCAFE);

    //--------------------------------------------------------------------
    // testing errno of syscalls without filter (close as example)
    //--------------------------------------------------------------------
    printf("testing close: ");
    int ret = close(-1);
    printf("ret=%d, errno=%d\n", ret, errno);
    assert(EBADF == errno);

    //--------------------------------------------------------------------
    // testing non accessible addresses as syscall arguments
    //--------------------------------------------------------------------
    printf("testing openat with NULL pointer\n");
    assert(syscall(SYS_openat, AT_FDCWD, (long)NULL, O_CREAT) == -1);
    assert(errno == EFAULT);

    if (sf_data.sf_filter_current == SF_SELF_OPEN
     || sf_data.sf_filter_current == SF_SELF
     || sf_data.sf_filter_current == SF_EXTENDED_DOMAIN
     || sf_data.sf_filter_current == SF_EXTENDED_MONITOR
    ) {
        printf("testing openat with protected pointer\n");
        assert(syscall(SYS_openat, AT_FDCWD, (long)protected, O_CREAT) == -1);
        assert(errno == EFAULT);
    }

    //--------------------------------------------------------------------
    // testing return value for SYSCALL_DENIED syscalls
    //--------------------------------------------------------------------
    printf("testing denied syscall 'bpf'\n");
    assert(syscall(SYS_bpf, 0, 0, 0) == -1);
    assert(errno == EPERM);

    //--------------------------------------------------------------------
    // testing if address for set_robust_list is checked
    //--------------------------------------------------------------------
    char ok[10];
    printf("testing set_robust_list with okay pointer\n");
    assert(syscall(SYS_set_robust_list, (long)ok, 10) == -1);

    printf("testing set_robust_list with protected pointer\n");
    assert(syscall(SYS_set_robust_list, (long)protected, 10) == -1);
    assert(errno == EFAULT);

}

void test7_localstorage_chdir()
{
    char cwd[PATH_MAX + 1];
    memset(cwd, 'a', sizeof(cwd));

    //--------------------------------------------------------------------
    // testing strlen(chdir) > PATH_MAX
    //--------------------------------------------------------------------
    printf("testing chdir with too long path: ");
    int ret = chdir(cwd);
    printf("ret=%d, errno=%d\n", ret, errno);
    assert(ret == -1);
    assert(errno == ENAMETOOLONG);

    //--------------------------------------------------------------------
    // testing strlen(base_path) + strlen(chdir) > PATH_MAX
    //--------------------------------------------------------------------
    printf("testing chdir with too long combined path: ");
    ret = chdir(cwd + 20);
    printf("ret=%d, errno=%d\n", ret, errno);
    assert(ret == -1);
    assert(errno == ENAMETOOLONG);

    //--------------------------------------------------------------------
    // testing nonexistent path
    //--------------------------------------------------------------------
    printf("testing chdir with nonexistent path\n");
    assert(chdir("/nonexistent") == -1);
    assert(errno == ENOENT);

    //--------------------------------------------------------------------
    // testing absolute path
    //--------------------------------------------------------------------
    printf("testing chdir with absolute path\n");
    assert(chdir("/testdir") == 0);

    //--------------------------------------------------------------------
    // testing getcwd
    //--------------------------------------------------------------------
    printf("testing getcwd: ");
    char *cwd1 = getcwd(cwd, 10);
    if (!cwd1) {
        perror("getcwd failed");
    }
    printf("ret='%s'\n", cwd);
    assert(cwd1 == cwd);
    assert(strcmp("/testdir", cwd) == 0);

    //--------------------------------------------------------------------
    // testing relative path
    //--------------------------------------------------------------------
    printf("testing chdir with relative path\n");
    assert(chdir("../..") == 0);

    //--------------------------------------------------------------------
    // testing getcwd
    //--------------------------------------------------------------------
    printf("testing getcwd: ");
    cwd1 = getcwd(cwd, 10);
    if (!cwd1) {
		perror("getcwd failed");
	}
    printf("ret='%s'\n", cwd);
    assert(cwd1 == cwd);
    assert(strcmp("/", cwd) == 0);

}

void test7_localstorage_filters()
{
    //--------------------------------------------------------------------
    // testing creating folder
    //--------------------------------------------------------------------
    printf("testing creating folder testdir\n");
    mkdir("/testdir", 0777); // can already be there
    assert(access("/testdir", R_OK) == 0);

    //--------------------------------------------------------------------
    // testing open / openat with localstorage filters
    //--------------------------------------------------------------------
    printf("testing opening folder .\n");
    int dirfd = open(".", O_RDONLY);
    if (dirfd == -1){
        perror("open failed");
    }
    assert(dirfd >= 0);

    printf("testing creating file at ../../test1.txt\n");
    int fd = openat(dirfd, "../../test1.txt", O_CREAT, 0777);
    if (fd == -1){
        perror("openat failed");
    }
    assert(fd >= 0);
    close(dirfd);
    close(fd);

    //--------------------------------------------------------------------
    // checking, if file was created
    //--------------------------------------------------------------------
    printf("testing, if created file is accessible\n");
    assert(access("/test1.txt", R_OK) == 0);


    //--------------------------------------------------------------------
    // testing chdir with localstorage filters
    //--------------------------------------------------------------------
    test7_localstorage_chdir();

    //--------------------------------------------------------------------
    // testing creating file relative to changed working directory
    //--------------------------------------------------------------------
    printf("testing creating file relative to changed cwd\n");
    fd = open("cwd/test2.txt", O_CREAT, 0777);
    assert(fd >= 0);
    close(fd);

    //--------------------------------------------------------------------
    // checking, if file was created
    //--------------------------------------------------------------------
    printf("testing, if created file is accessible\n");
    assert(access("/cwd/test2.txt", R_OK) == 0);
}

void *thread(void *arg)
{
    printf("-------------------------------------------\n");
    printf("testing inside of pthread\n");
    printf("testing return value of filtered syscalls: ");
    unsigned long val = (unsigned long)syscall(SYS_test_return_value);
    printf("ret=0x%lx\n", val);
    if (sf_data.sf_filter_current == SF_NONE) {
        assert(val == (unsigned long)-1);
    } else {
        assert(0xC0FEC0FE == val);
    }
    return (void *)0x1234;
}

void test7_binscan()
{
    if(!pk_data.binary_scanning){
        return;
    }

    printf("test7_binscan\n");

    FILE *fp;
    fp  = fopen("test7_binscan.txt", "w+");
    assert(fp != NULL);
    fputs("test\n", fp);
    fclose (fp);

    int fd  = open("test7_binscan.txt", O_RDONLY);
    assert(fd != -1);
    void * map = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_EXEC, MAP_PRIVATE, fd, 0);
    assert(map == MAP_FAILED);
    close(fd);
}

void test7(int *protected)
{
    #ifndef RELEASE
    pk_print_current_reg();
    #endif

    test7_binscan();

    if (sf_data.sf_filter_current > SF_NONE) {
        printf("-------------------------------------------\n");
        printf("testing monitor filters\n");
        test7_monitor_filters(protected);
    }

    //NOTE: this doesnt work for SF_SELF_DONKY SF_SELF_DONKY in debug mode because we disabled the prctl protection
    if (sf_data.sf_filter_current == SF_SELF || 
        sf_data.sf_filter_current == SF_SELF_OPEN
    ) {
        printf("-------------------------------------------\n");
        printf("testing path sanitization filters\n");
        test7_path_sanitization();
    }
    else if (sf_data.sf_filter_current == SF_EXTENDED_MONITOR) {
        printf("-------------------------------------------\n");
        printf("testing localstorage filters (in monitor)\n");
        test7_localstorage_filters();
    }

    // These mechanisms do not support pthreads
    if (sf_data.sf_mechanism_current != SF_SECCOMP_USER &&
        sf_data.sf_mechanism_current != SF_PTRACE &&
        sf_data.sf_mechanism_current != SF_PTRACE_SECCOMP) {
        pthread_t tid;
        long ret;
        pk_pthread_create(&tid, NULL, thread, NULL);
        pthread_join(tid, (void **)&ret);
        printf("testing return value of pthread join: ret=0x%lx\n", ret);
        assert(ret == 0x1234);
    }

    if (sf_data.sf_mechanism_current == SF_NONE || sf_data.sf_filter_current == SF_NONE) {
        ERROR("skipping test7 as no syscall filters are installed");
        return;
    }

    if (sf_data.sf_mechanism_current != SF_PTRACE_DELEGATE && sf_data.sf_mechanism_current != SF_INDIRECT && sf_data.sf_mechanism_current != SF_USERMODE && sf_data.sf_mechanism_current != SF_SYSMODULE) {
        WARNING("skipping nested test as the filtering mechanism %s does not support them", mechanism_str(sf_data.sf_mechanism_current));
        return;
    }

    // setup nested tests
    printf("-------------------------------------------\n");
    printf("setting up domain for nested filtering\n");
    int domain = pk_domain_create(PK_KEY_INHERIT | PK_KEY_COPY);
    assert(domain > 0);
    ecall_register_test7_nested(domain);
    pk_domain_allow_caller2(domain, pk_current_did(), 0);
    pk_sysfilter_domain(domain, SYS_getuid, test7_getuid_filter, NULL);
    pk_sysfilter_domain(domain, SYS_test_return_value, test7_test_return_value_filter, NULL);


    printf("-------------------------------------------\n");
    if (sf_data.sf_filter_current == SF_EXTENDED_DOMAIN) {
        printf("testing custom nested filters with extended filters\n");
        // extended filters are already initialized in main/ctor
        ecall_test7_nested(true);
    }
    else {
        printf("testing custom nested filters\n");
        ecall_test7_nested(false);
    }

    // of the above methods, only one ptrace reaches here
    // again, ptrace does not support fork
    if (sf_data.sf_mechanism_current == SF_PTRACE_DELEGATE) {
        goto cleanup; 
    }
    printf("-------------------------------------------\n");
    printf("Testing nested within fork-child\n");
    pid_t child = fork();
    assert(-1 != child);
    if (child == 0) {
        // child 
        ecall_test7_nested(false);

        printf("Testing nested within fork-subchild\n");
        pid_t subchild = fork();
        assert(-1 != subchild);
        if (subchild == 0) {
            // subchild 
            ecall_test7_nested(false);
            // in case PRELOAD is not active, deinit manually.
            // otherwise exit could fail with a PKU segfault
            pk_deinit();
            exit(1);
        }

        int subresult = 0;
        assert(waitpid(subchild, &subresult, 0) > 0);
        printf("waitpid returned %d result %d\n", subresult, WEXITSTATUS(subresult));
        assert(WIFEXITED(subresult));
        assert(WEXITSTATUS(subresult) == 1);
        printf("done fork-subchild\n");
        // in case PRELOAD is not active, deinit manually.
        // otherwise exit could fail with a PKU segfault
        pk_deinit();
        exit(0);
    }
    // parent
    int result = 0;
    assert(waitpid(child, &result, 0) > 0);
    printf("waitpid returned %d result %d\n", result, WEXITSTATUS(result));
    assert(WIFEXITED(result));
    assert(WEXITSTATUS(result) == 0);
    printf("done fork-child\n");

    printf("Testing nested within fork-parent\n");
    ecall_test7_nested(false);
    printf("done fork-parent\n");

cleanup:
    assert(pk_domain_free(domain) == 0);
}

void test7_nested(bool localstorage_filters)
{
    #ifndef RELEASE
    pk_print_current_reg();
    #endif

    //--------------------------------------------------------------------
    // testing getuid with domain filter
    //--------------------------------------------------------------------
    printf("testing getuid: ");
    uid_t filtered_uid = getuid();
    printf("ret=0x%x\n", filtered_uid);
    assert(0x12345678 == filtered_uid);

    //--------------------------------------------------------------------
    // testing test_return_value with domain and monitor filter
    //--------------------------------------------------------------------
    printf("testing test_return_value: ");
    unsigned long val = (unsigned long)syscall(SYS_test_return_value);
    printf("ret=0x%lx\n", val);
    assert(0xC0FE == val);

    //--------------------------------------------------------------------
    // testing non accessible addresses as syscall arguments
    //--------------------------------------------------------------------
    printf("testing openat with bad pointers\n");
    assert(syscall(SYS_openat, AT_FDCWD, (long)NULL, O_CREAT) == -1);
    assert(errno == EFAULT);

    //--------------------------------------------------------------------
    // testing errno of syscalls with domain filter (close as example)
    //--------------------------------------------------------------------
    printf("testing close: ");
    int ret = close(-1);
    int errno_copy = errno;
    printf("ret=%d, errno=%d\n", ret, errno_copy);
    assert(EBADF == errno_copy);

    if (localstorage_filters) {
        printf("testing localstorage filters (in domain)\n");
        test7_localstorage_filters();
    }
}
