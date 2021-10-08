#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/types.h>
#include <sys/wait.h>
#include "sysfilter.h"

#define HAS_PKRU 1

#define SECURE_MONITOR "\x1b[32m"
#define SECURE_MONITOR_END "\x1b[0m"

char __attribute__((aligned(4096))) dummy[4096];
int sysfilter_fd = -1;

// ---------------------------------------------------------------------------
void test() {
    char res = 0;
    *(char volatile*)dummy;
    printf("[~] Executing mincore(%p, 4096, %p) from %p\n", dummy, &res, test);
    int ret = mincore(dummy, 4096, &res);
//     printf("PID: %d\nResult: %d, Cache: %d\n", getpid(), ret, res);
    printf("[~] Returned: %d\n", ret);
    if(res) printf("[+] Mincore not blocked\n");
    else printf("[-] Mincore blocked\n");
}

// ---------------------------------------------------------------------------
void write_pkru(int key) {
    if (HAS_PKRU) {
        printf("[~] Writing protection key 0x%x\n", key);
        __asm__ volatile(
          "xor %%ecx, %%ecx\n" // clear ecx
          "xor %%edx, %%edx\n" // clear edx
          "wrpkru"
          : /* no outputs */
          : "a"(key)
          : "rcx", "rdx"
        );
    } else {
        printf("[~] Simluate writing protection key 0x%x\n", key);
        ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_WRITEKEY, key);
    }
}

// ---------------------------------------------------------------------------
int read_pkru() {
    int ret;
    if (HAS_PKRU) {
        // https://www.felixcloutier.com/x86/rdpkru
        __asm__ volatile(
          "xor %%ecx, %%ecx\n"
          "rdpkru"
          : "=a"(ret)
          : /* no inputs */
          : "rdx"
        );
        return ret;
    } else {
        printf("[~] Simluate reading protection key ");
        int key = ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_READKEY);
        printf("0x%x\n", key);
        return key;
    }
}


// ---------------------------------------------------------------------------
size_t __attribute__((section(".ssm"))) secure_monitor_c(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6, uintptr_t sysno) {

    printf(SECURE_MONITOR);
    printf("[~] Inside secure syscall monitor\n");
    int oldpkru = read_pkru();
    printf("[~] PKRU: save old value 0x%x\n", oldpkru);
    printf("[~] PKRU: set to 0\n");
    write_pkru(0);

    printf("[~] Syscall no %zd (0x%zx, 0x%zx, 0x%zx, 0x%zx, 0x%zx, 0x%zx)\n", (size_t)sysno, (size_t)arg1, (size_t)arg2, (size_t)arg3, (size_t)arg4, (size_t)arg5, (size_t)arg6);

    printf("[+] Allowing syscall\n");
    long ret = syscall(sysno, arg1, arg2, arg3, arg4, arg5, arg6);

    if(sysno == SYS_mincore) {
        printf("[+] Mincore: returning 55\n");
        ret = 55;
    }

    printf("[~] PKRU: restore old value\n");
    write_pkru(oldpkru);
    printf("[~] PKRU: set to 0x%x\n", read_pkru());
    printf(SECURE_MONITOR_END);
    return ret;
}

// ---------------------------------------------------------------------------
size_t __attribute__((naked, section(".ssm"))) secure_monitor_asm() {
    // Switch from syscall ABI to normal ABI
    asm volatile(
        "push %rcx\n"
        "push %rax\n"
        "addq $-8, %rsp\n"
        "mov %r10, %rcx\n"
        "call secure_monitor_c\n"
        "addq $16, %rsp\n"
        "retq\n");
}

// ---------------------------------------------------------------------------
void* thread(void* arg) {
    //child
    printf("[~] Syscall shall be blocked for child\n");
    test();
    return 0;
}

// ---------------------------------------------------------------------------
int main() {
    int ret;
    memset(dummy, 1, sizeof(dummy));
    
    sysfilter_fd = open(SYSFILTER_DEVICE_PATH, O_RDONLY);
    if (sysfilter_fd < 0) {
        fprintf(stderr, "[-] Error: Could not open Sysfilter device: %s\n", SYSFILTER_DEVICE_PATH);
        return -1;
    }
    ret = ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_KILL_ON_VIOLATION, 0);
    assert(0 == ret);

    printf("[~] Sanity check protection keys\n");
    int orig_key = read_pkru();
    write_pkru(0x12340000);
    if (read_pkru() != 0x12340000) {
        fprintf(stderr, "[-] Error: Could not write protection key");
        return -1;
    }
    write_pkru(orig_key);
    if (read_pkru() != orig_key) {
        fprintf(stderr, "[-] Error: Could not write protection key");
        return -1;
    }

    printf("[~] Apply filter to current PID: %d\n", getpid());
    ret = ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_PID, getpid());
    assert(0 == ret);

    printf("[~] Register monitor: %p\n", &secure_monitor_asm);
    ret = ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_REGISTER_MONITOR, &secure_monitor_asm);
    assert(0 == ret);

    printf("[~] Block mincore syscall (syscall number 27)\n");
    ret = ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_BLOCK, SYS_mincore);
    assert(0 == ret);

    printf("[~] Block clone syscall\n");
    ret = ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_BLOCK, SYS_clone);
    assert(0 == ret);
    ret = ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_BLOCK, SYS_clone3);
    assert(0 == ret);
    ret = ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_BLOCK, SYS_fork);
    assert(0 == ret);
    ret = ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_BLOCK, SYS_vfork);
    assert(0 == ret);

    printf("[~] Syscall should be allowed\n");
    test();

    printf("[~] Enable delegation\n");
    write_pkru(orig_key | SYSFILTER_DELEGATE_MASK);
    printf("[~] Syscall should be delegated, jumps into secure handler\n");
    test();

    printf("[~] Ioctl should be blocked outside monitor\n");
    ret = ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_BLOCK, SYS_rt_sigaction);
    assert(ret == -1);

    printf("[~] Resetting protection key\n");
    write_pkru(orig_key);
    printf("[~] Syscall should be allowed\n");
    test();

    printf("[~] Ioctl should be allowed again (inside monitor)\n");
    ret = ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_BLOCK, SYS_rt_sigaction);
    assert(ret == 0);
    //~ printf("[~] Simluate writing protection key 1 and kill on violation\n");
    //~ printf("[~] Enable delegation\n");
    //~ write_pkru(orig_key | SYSFILTER_DELEGATE_MASK);
    //~ ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_KILL_ON_VIOLATION, 1);

    //~ pthread_t child;
    //~ if (pthread_create(&child, NULL, thread, NULL)) {
        //~ printf("pthread_create failed\n");
        //~ return -1;
    //~ }
    //~ int retval = 0;
    //~ if (pthread_join(child, (void**)&retval)) {
        //~ printf("pthread_join failed\n");
        //~ return -1;
    //~ }
    //~ if (0 == retval) {
        //~ printf("[~] Unexpected child exit code: %d, should not be 0\n", retval);
        //~ return -1;
    //~ }

    pid_t childproc = fork();
    printf("[~] forked: %d\n", childproc);
    switch (childproc) {
        case 0:
            exit(0);
        default:
            waitpid(childproc, NULL, 0);
    }

    printf("[~] Unblock mincore syscall\n");
    ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_UNBLOCK, 27);
    printf("[~] Remove PID filter\n");
    ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_PID, 0);

    close(sysfilter_fd);
}
