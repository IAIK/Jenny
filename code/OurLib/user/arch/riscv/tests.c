#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "test2_ecall.h"
#include "pk.h"

int test_syscall_args();

void ecall_register_test2(int dom) {
    ecall_register_test_args(dom);
    ecall_register_test_api_calls(dom);
    ecall_register_test_kill_all_regs(dom);
    ecall_register_test_syscall_args(dom);
}

int __attribute__((naked)) more_test_kill_all_regs(){
        asm volatile (
        //saving registers
        "addi    sp, sp, -28*8;"
        "sd      s1,  27*8(sp);"
        "sd      s2,  26*8(sp);"
        "sd      s3,  25*8(sp);"
        "sd      s4,  24*8(sp);"
        "sd      s5,  23*8(sp);"
        "sd      s6,  22*8(sp);"
        "sd      s7,  21*8(sp);"
        "sd      s8,  20*8(sp);"
        "sd      s9,  19*8(sp);"
        "sd     s10,  18*8(sp);"
        "sd     s11,  17*8(sp);"
        "sd      ra,  16*8(sp);"
        "sd      t0,  15*8(sp);"
        "sd      t1,  14*8(sp);"
        "sd      t2,  13*8(sp);"
        "sd      s0,  12*8(sp);"
        "sd      a0,  11*8(sp);"
        "sd      a1,  10*8(sp);"
        "sd      a2,   9*8(sp);"
        "sd      a3,   8*8(sp);"
        "sd      a4,   7*8(sp);"
        "sd      a5,   6*8(sp);"
        "sd      a6,   5*8(sp);"
        "sd      a7,   4*8(sp);"
        "sd      t3,   3*8(sp);"
        "sd      t4,   2*8(sp);"
        "sd      t5,   1*8(sp);"
        "sd      t6,   0*8(sp);"

        "call ecall_test_kill_all_regs;"

        //check if callee-saved registers changed during the ecall
        "ld      a0,  27*8(sp); sub a0, a0,  s1; bnez a0, error;"
        "ld      a0,  26*8(sp); sub a0, a0,  s2; bnez a0, error;"
        "ld      a0,  25*8(sp); sub a0, a0,  s3; bnez a0, error;"
        "ld      a0,  24*8(sp); sub a0, a0,  s4; bnez a0, error;"
        "ld      a0,  23*8(sp); sub a0, a0,  s5; bnez a0, error;"
        "ld      a0,  22*8(sp); sub a0, a0,  s6; bnez a0, error;"
        "ld      a0,  21*8(sp); sub a0, a0,  s7; bnez a0, error;"
        "ld      a0,  20*8(sp); sub a0, a0,  s8; bnez a0, error;"
        "ld      a0,  19*8(sp); sub a0, a0,  s9; bnez a0, error;"
        "ld      a0,  18*8(sp); sub a0, a0, s10; bnez a0, error;"
        "ld      a0,  17*8(sp); sub a0, a0, s11; bnez a0, error;"
        //"ld      a0,  16*8(sp); sub a0, a0,  ra; bnez a0, error;"
        //"ld      a0,  15*8(sp); sub a0, a0,  t0; bnez a0, error;"
        //"ld      a0,  14*8(sp); sub a0, a0,  t1; bnez a0, error;"
        //"ld      a0,  13*8(sp); sub a0, a0,  t2; bnez a0, error;"
        "ld      a0,  12*8(sp); sub a0, a0,  s0; bnez a0, error;"
        //"ld      a0,  10*8(sp); sub a0, a0,  a1; bnez a0, error;"
        //"ld      a0,   9*8(sp); sub a0, a0,  a2; bnez a0, error;"
        //"ld      a0,   8*8(sp); sub a0, a0,  a3; bnez a0, error;"
        //"ld      a0,   7*8(sp); sub a0, a0,  a4; bnez a0, error;"
        //"ld      a0,   6*8(sp); sub a0, a0,  a5; bnez a0, error;"
        //"ld      a0,   5*8(sp); sub a0, a0,  a6; bnez a0, error;"
        //"ld      a0,   3*8(sp); sub a0, a0,  t3; bnez a0, error;"
        //"ld      a0,   2*8(sp); sub a0, a0,  t4; bnez a0, error;"
        //"ld      a0,   1*8(sp); sub a0, a0,  t5; bnez a0, error;"
        //"ld      a0,   0*8(sp); sub a0, a0,  t6; bnez a0, error;"

        "li a0, 0;" //return value for success
        "j end;"
        "error:"
        "li a0, 1;" //return value for error

        //end: restore registers and return
        "end:"
        //restore registers
        "ld      s1,  27*8(sp);"
        "ld      s2,  26*8(sp);"
        "ld      s3,  25*8(sp);"
        "ld      s4,  24*8(sp);"
        "ld      s5,  23*8(sp);"
        "ld      s6,  22*8(sp);"
        "ld      s7,  21*8(sp);"
        "ld      s8,  20*8(sp);"
        "ld      s9,  19*8(sp);"
        "ld     s10,  18*8(sp);"
        "ld     s11,  17*8(sp);"
        "ld      ra,  16*8(sp);"
        "ld      t0,  15*8(sp);"
        "ld      t1,  14*8(sp);"
        "ld      t2,  13*8(sp);"
        "ld      s0,  12*8(sp);"
        //"ld      a0,  11*8(sp);" //return value
        "ld      a1,  10*8(sp);"
        "ld      a2,   9*8(sp);"
        "ld      a3,   8*8(sp);"
        "ld      a4,   7*8(sp);"
        "ld      a5,   6*8(sp);"
        "ld      a6,   5*8(sp);"
        "ld      a7,   4*8(sp);"
        "ld      t3,   3*8(sp);"
        "ld      t4,   2*8(sp);"
        "ld      t5,   1*8(sp);"
        "ld      t6,   0*8(sp);"
        "addi    sp, sp, 28*8;"

        "ret;"
        : /* output */
        : /* input */
    );
}

int __attribute__((naked)) test_api_calls_and_registers(){
        asm volatile (
        //saving registers
        "addi    sp, sp, -28*8;"
        "sd      s1,  27*8(sp);"
        "sd      s2,  26*8(sp);"
        "sd      s3,  25*8(sp);"
        "sd      s4,  24*8(sp);"
        "sd      s5,  23*8(sp);"
        "sd      s6,  22*8(sp);"
        "sd      s7,  21*8(sp);"
        "sd      s8,  20*8(sp);"
        "sd      s9,  19*8(sp);"
        "sd     s10,  18*8(sp);"
        "sd     s11,  17*8(sp);"
        "sd      ra,  16*8(sp);"
        "sd      t0,  15*8(sp);"
        "sd      t1,  14*8(sp);"
        "sd      t2,  13*8(sp);"
        "sd      s0,  12*8(sp);"
        "sd      a0,  11*8(sp);"
        "sd      a1,  10*8(sp);"
        "sd      a2,   9*8(sp);"
        "sd      a3,   8*8(sp);"
        "sd      a4,   7*8(sp);"
        "sd      a5,   6*8(sp);"
        "sd      a6,   5*8(sp);"
        "sd      a7,   4*8(sp);"
        "sd      t3,   3*8(sp);"
        "sd      t4,   2*8(sp);"
        "sd      t5,   1*8(sp);"
        "sd      t6,   0*8(sp);"

        "addi     sp,sp,-8;"
        "sd       ra,0(sp);"
        //"call     pk_print_debug_info;"
        "call     pk_print_current_reg;"
        "ld       ra,0(sp);"
        "addi     sp,sp,8;"

        //check if callee-saved registers changed during the ecall
        "ld      a0,  27*8(sp); sub a0, a0,  s1; bnez a0, 1f;"
        "ld      a0,  26*8(sp); sub a0, a0,  s2; bnez a0, 1f;"
        "ld      a0,  25*8(sp); sub a0, a0,  s3; bnez a0, 1f;"
        "ld      a0,  24*8(sp); sub a0, a0,  s4; bnez a0, 1f;"
        "ld      a0,  23*8(sp); sub a0, a0,  s5; bnez a0, 1f;"
        "ld      a0,  22*8(sp); sub a0, a0,  s6; bnez a0, 1f;"
        "ld      a0,  21*8(sp); sub a0, a0,  s7; bnez a0, 1f;"
        "ld      a0,  20*8(sp); sub a0, a0,  s8; bnez a0, 1f;"
        "ld      a0,  19*8(sp); sub a0, a0,  s9; bnez a0, 1f;"
        "ld      a0,  18*8(sp); sub a0, a0, s10; bnez a0, 1f;"
        "ld      a0,  17*8(sp); sub a0, a0, s11; bnez a0, 1f;"
        //"ld      a0,  16*8(sp); sub a0, a0,  ra; bnez a0, 1f;"
        //"ld      a0,  15*8(sp); sub a0, a0,  t0; bnez a0, 1f;"
        //"ld      a0,  14*8(sp); sub a0, a0,  t1; bnez a0, 1f;"
        //"ld      a0,  13*8(sp); sub a0, a0,  t2; bnez a0, 1f;"
        "ld      a0,  12*8(sp); sub a0, a0,  s0; bnez a0, 1f;"
        //"ld      a0,  10*8(sp); sub a0, a0,  a1; bnez a0, 1f;"
        //"ld      a0,   9*8(sp); sub a0, a0,  a2; bnez a0, 1f;"
        //"ld      a0,   8*8(sp); sub a0, a0,  a3; bnez a0, 1f;"
        //"ld      a0,   7*8(sp); sub a0, a0,  a4; bnez a0, 1f;"
        //"ld      a0,   6*8(sp); sub a0, a0,  a5; bnez a0, 1f;"
        //"ld      a0,   5*8(sp); sub a0, a0,  a6; bnez a0, 1f;"
        //"ld      a0,   3*8(sp); sub a0, a0,  t3; bnez a0, 1f;"
        //"ld      a0,   2*8(sp); sub a0, a0,  t4; bnez a0, 1f;"
        //"ld      a0,   1*8(sp); sub a0, a0,  t5; bnez a0, 1f;"
        //"ld      a0,   0*8(sp); sub a0, a0,  t6; bnez a0, 1f;"

        "li a0, 0;" //return value for success
        "j 2f;"
        "1:"
        "li a0, 1;" //return value for error

        //end: restore registers and return
        "2:"
        //restore registers
        "ld      s1,  27*8(sp);"
        "ld      s2,  26*8(sp);"
        "ld      s3,  25*8(sp);"
        "ld      s4,  24*8(sp);"
        "ld      s5,  23*8(sp);"
        "ld      s6,  22*8(sp);"
        "ld      s7,  21*8(sp);"
        "ld      s8,  20*8(sp);"
        "ld      s9,  19*8(sp);"
        "ld     s10,  18*8(sp);"
        "ld     s11,  17*8(sp);"
        "ld      ra,  16*8(sp);"
        "ld      t0,  15*8(sp);"
        "ld      t1,  14*8(sp);"
        "ld      t2,  13*8(sp);"
        "ld      s0,  12*8(sp);"
        //"ld      a0,  11*8(sp);" //return value
        "ld      a1,  10*8(sp);"
        "ld      a2,   9*8(sp);"
        "ld      a3,   8*8(sp);"
        "ld      a4,   7*8(sp);"
        "ld      a5,   6*8(sp);"
        "ld      a6,   5*8(sp);"
        "ld      a7,   4*8(sp);"
        "ld      t3,   3*8(sp);"
        "ld      t4,   2*8(sp);"
        "ld      t5,   1*8(sp);"
        "ld      t6,   0*8(sp);"
        "addi    sp, sp, 28*8;"

        "ret;"
        : /* output */
        : /* input */
    );
}

void test2() {
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
    printf("Calling ecall_test_kill_all_regs\n");
    ret = (uint64_t)ecall_test_kill_all_regs();
    assert(ret == 0xF0);

    //same test, but this time check all register values (not just the return value)
    printf("Calling more_test_kill_all_regs\n");
    ret = (uint64_t)more_test_kill_all_regs();
    assert(ret == 0);

    //----------------------------------------------------------------------------
    // Test API calls within an ecall
    printf("Calling ecall_test_api_calls\n");
    ecall_test_api_calls();

    printf("Calling test_api_calls_and_registers\n");
    ret = (uint64_t) test_api_calls_and_registers();
    assert(ret == 0);

    //----------------------------------------------------------------------------
    // Test syscall argument preservation
    printf("Calling test_syscall_args directly\n");
    ret = (uint64_t) test_syscall_args();
    assert(ret == 0);

    printf("Calling ecall_test_syscall_args\n");
    ret = (uint64_t) ecall_test_syscall_args();
    assert(ret == 0);

}
