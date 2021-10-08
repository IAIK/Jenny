#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "test2_ecall.h"
#include "pk.h"

extern int test_syscall_args();
extern int test_syscall_function_args();

void ecall_register_test2(int dom) {
    ecall_register_test_args(dom);
    ecall_register_test_api_calls(dom);
    ecall_register_test_kill_all_regs(dom);
    ecall_register_test_syscall_args(dom);
    ecall_register_test_syscall_function_args(dom);
}

void test2() {
    printf("test2\n");

    //----------------------------------------------------------------------------
    // Test if function arguments / return values are passed correctly
    printf("Calling ecall_test_args\n");
    uint64_t ret;

    ret = ecall_test_args(0x10, 0x11, 0x12, 0x13, 0x14, 0x15);
    printf("ecall_test_args returned %lx\n", ret);
    assert(ret == 0xAABBCCDD00112233ULL);

    //----------------------------------------------------------------------------
    // Test if callee-saved registers are preserved by wrapper in case a
    // malicious ecall target does not preserve them
    register int rbx asm("rbx"), r12 asm("r12"), r13 asm("r13"), r14 asm("r14"), r15 asm("r15");
    asm volatile(
    "mov $0x11, %%rbx\n"
    "mov $0x22, %%r12\n"
    "mov $0x33, %%r13\n"
    "mov $0x44, %%r14\n"
    "mov $0x55, %%r15\n"
    "call ecall_test_kill_all_regs\n"
    : "=r"(rbx), "=r"(r12), "=r"(r13), "=r"(r14), "=r"(r15));
    assert(rbx == 0x11);
    assert(r12 == 0x22);
    assert(r13 == 0x33);
    assert(r14 == 0x44);
    assert(r15 == 0x55);

    //----------------------------------------------------------------------------
    // Test API calls within an ecall
    printf("Calling ecall_test_api_calls\n");
    ecall_test_api_calls();

    //----------------------------------------------------------------------------
    // Test syscall argument preservation
    printf("Calling test_syscall_args directly\n");
    ret = (uint64_t) test_syscall_args();
    if (ret > 0) {
        printf("test_syscall_args got mismatch on register push no. %zu\n", ret);
    }
    assert(ret == 0);

    printf("Calling ecall_test_syscall_args\n");
    ret = (uint64_t) ecall_test_syscall_args();
    assert(ret == 0);

    //----------------------------------------------------------------------------
    // Test syscall argument preservation when calling syscall function
    // (test for mechansim indirect)
    printf("Calling test_syscall_function_args directly\n");
    ret = (uint64_t) test_syscall_function_args();
    if (ret > 0) {
        printf("test_syscall_function_args got mismatch on register push no. %zu\n", ret);
    }
    assert(ret == 0);

    printf("Calling ecall_test_syscall_function_args\n");
    ret = (uint64_t) ecall_test_syscall_function_args();
    assert(ret == 0);
}
