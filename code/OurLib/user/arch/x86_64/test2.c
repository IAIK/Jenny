#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/syscall.h>

#include "test2_ecall.h"
#include "test3_ecall.h"
#include "pk_debug.h"



uint64_t test_args(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f) {
  //printf("%lx %lx %lx %lx %lx %lx\n", a, b, c, d, e, f);
  #ifndef TIMING
    assert(a == 0x10);
    assert(b == 0x11);
    assert(c == 0x12);
    assert(d == 0x13);
    assert(e == 0x14);
    assert(f == 0x15);
  #endif
  return 0xAABBCCDD00112233ULL;
}

int test2_nested(int arg){
    DEBUG_MPK("test2_nested(%d)\n", arg);
    //pk_print_current_reg();
    arg--;
    if(arg > 0){
        DEBUG_MPK("test2_nested: Calling test3_nested(%d)\n", arg);
        int ret = ecall_test3_nested(arg);
        DEBUG_MPK("test2_nested: Successfully called ecall_test3_nested(%d). return value was %d\n", arg, ret);
        assert(ret == arg - 1);
    }else{
      #ifndef RELEASE
        pk_print_debug_info();
      #endif
    }
    return arg;
}

void test_api_calls() {
  pk_print_debug_info();
  pk_print_current_reg();
}

int __attribute__((naked)) test_kill_all_regs() {
  asm volatile (
    // Write callee-saved registers
    "mov $0xFF, %rbx\n"
    "mov $0xEE, %r12\n"
    "mov $0xDD, %r13\n"
    "mov $0xCC, %r14\n"
    "mov $0xBB, %r15\n"
    // Return
    "mov $0xAA, %rax\n"
    "mov $0x99, %rdx\n"
    "ret\n"
    );
}

int __attribute__((naked)) test_syscall_function_args(){
    asm volatile (
        //saving registers.
        // only rcx and r11 are clobbered by syscall, rax contains the return value.
        "movq %0, %%rdi\n"
        "push %%rbx\n" //preserved across function calls
        //"push %%rcx\n"
        //"push %%rdx\n"
        "push %%rsp\n" //preserved across function calls
        "push %%rbp\n" //preserved across function calls
        //"push %%rsi\n"
        //"push %%rdi\n"
        //"push %%r8\n"
        //"push %%r9\n"
        //"push %%r10\n"
        //"push %%r11\n"
        "push %%r12\n" //preserved across function calls
        "push %%r13\n" //preserved across function calls
        "push %%r14\n" //preserved across function calls
        "push %%r15\n" //preserved across function calls

        "call syscall\n"

		"xor %%eax, %%eax\n"

        //check if registers changed during the syscall
        //using r11 as temporary register
        "pop %%r11\n cmp %%r11, %%r15\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%r14\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%r13\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%r12\n cmovnz %%rsp, %%rax\n"
        //"pop %%r11\n cmp %%r11, %%r11\n cmovnz %%rsp, %%rax\n"
        //"pop %%r11\n cmp %%r11, %%r10\n cmovnz %%rsp, %%rax\n"
        //"pop %%r11\n cmp %%r11, %%r9\n cmovnz %%rsp, %%rax\n"
        //"pop %%r11\n cmp %%r11, %%r8\n cmovnz %%rsp, %%rax\n"
        //"pop %%r11\n cmp %%r11, %%rdi\n cmovnz %%rsp, %%rax\n"
        //"pop %%r11\n cmp %%r11, %%rsi\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%rbp\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%rsp\n cmovnz %%rsp, %%rax\n"
        //"pop %%r11\n cmp %%r11, %%rdx\n cmovnz %%rsp, %%rax\n"
        //"pop %%r11\n cmp %%r11, %%rcx\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%rbx\n cmovnz %%rsp, %%rax\n"
        //"pop %%r11\n cmp %%r11, %%rax\n cmovnz %%rsp, %%rax\n"

		"test %%rax, %%rax\n"
		"jz 1f\n"
		"subq %%rsp, %%rax\n" // compute where a mismatch occurred
		"neg %%rax\n"
		"shr $3, %%rax\n"     // count slots rather than bytes
		"add $1, %%rax\n"     // fix off-by-one offset
        "1:"
        "ret\n"
        : /* output */
        : /*input*/ [_syscall_nr] "i"(__NR_getppid)
    );
}

int __attribute__((naked)) test_syscall_args(){
    asm volatile (
        //saving registers.
        // only rcx and r11 are clobbered by syscall, rax contains the return value.
        "add $-8, %%rsp\n" // PSABI alignment
        "mov $55, %%rdi\n"
        "mov $55, %%rsi\n"
        "mov $55, %%rdx\n"
        "mov $55, %%rcx\n"
        "mov $55, %%r8\n"
        "mov $55, %%r9\n"
        "mov $55, %%r10\n"
        "mov $55, %%r11\n"
        //"push %%rax\n"
        "push %%rbx\n" //preserved across function calls
        //"push %%rcx\n"
        "push %%rdx\n"
        "push %%rsp\n" //preserved across function calls
        "push %%rbp\n" //preserved across function calls
        "push %%rsi\n"
        "push %%rdi\n"
        "push %%r8\n"
        "push %%r9\n"
        "push %%r10\n"
        //"push %%r11\n"
        "push %%r12\n" //preserved across function calls
        "push %%r13\n" //preserved across function calls
        "push %%r14\n" //preserved across function calls
        "push %%r15\n" //preserved across function calls

        "syscall\n"

        "xor %%eax, %%eax\n"

        //check if registers changed during the syscall
        //using r11 as temporary register
        "pop %%r11\n cmp %%r11, %%r15\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%r14\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%r13\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%r12\n cmovnz %%rsp, %%rax\n"
        //"pop %%r11\n cmp %%r11, %%r11\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%r10\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%r9\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%r8\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%rdi\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%rsi\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%rbp\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%rsp\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%rdx\n cmovnz %%rsp, %%rax\n"
        //"pop %%r11\n cmp %%r11, %%rcx\n cmovnz %%rsp, %%rax\n"
        "pop %%r11\n cmp %%r11, %%rbx\n cmovnz %%rsp, %%rax\n"
        //"pop %%r11\n cmp %%r11, %%rax\n cmovnz %%rsp, %%rax\n"

        "test %%rax, %%rax\n"
        "jz 1f\n"
        "subq %%rsp, %%rax\n" // compute where a mismatch occurred
        "neg %%rax\n"
        "shr $3, %%rax\n"     // count slots rather than bytes
        "add $1, %%rax\n"     // fix off-by-one offset
        "1:"
        "add $8, %%rsp\n"
        "ret\n"
        : /* output */
        : /*input*/ [_syscall_nr] "a"(__NR_getpid)
    );
}
