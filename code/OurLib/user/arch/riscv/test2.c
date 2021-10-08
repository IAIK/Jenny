#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/syscall.h>

#include "test2_ecall.h"
#include "test3_ecall.h"
#include "pk_debug.h"



uint64_t test_args(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f) {
  #ifndef RELEASE
      printf("%lx %lx %lx %lx %lx %lx\n", a, b, c, d, e, f);
  #endif
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
        #ifndef TIMING
          assert(ret == arg - 1);
        #endif
    }else{
      #ifndef RELEASE
        pk_print_debug_info();
      #endif
    }
    return arg;
}

void __attribute__((naked)) test_api_calls() {
    asm volatile (
    "addi     sp,sp,-8;"
    "sd       ra,0(sp);"
    "call     pk_print_debug_info;"
    "call     pk_print_current_reg;"
    "ld       ra,0(sp);"
    "addi     sp,sp,8;"
    "ret;"
    );
}

int __attribute__((naked)) test_kill_all_regs(){
    asm volatile (
    //TODO overwrite sp and all others (except ra)
    //TODO destroy entire stack
    "li    t0,  0xFF;"
    "li    t1,  0xFF;"
    "li    t2,  0xFF;"
    "li    s1,  0xFF;"
    "li    a0,  0xF0;"
    "li    a1,  0xF1;"
    "li    a2,  0xF2;"
    "li    a3,  0xFF;"
    "li    a4,  0xFF;"
    "li    a5,  0xFF;"
    "li    a6,  0xFF;"
    "li    a7,  0xFF;"
    "li    s2,  0xFF;"
    "li    s3,  0xFF;"
    "li    s4,  0xFF;"
    "li    s5,  0xFF;"
    "li    s6,  0xFF;"
    "li    s7,  0xFF;"
    "li    s8,  0xFF;"
    "li    s9,  0xFF;"
    "li    s10, 0xFF;"
    "li    s11, 0xFF;"
    "li    t3,  0xFF;"
    "li    t4,  0xFF;"
    "li    t5,  0xFF;"
    "li    t6,  0xFF;"
    "ret;"
    );
}

int __attribute__((naked)) test_syscall_args(){
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

        "li a7, %[_syscall_nr];"
        "ecall;"


        //check if registers changed during the syscall
        //excl a7, a0
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
        "ld      a0,  16*8(sp); sub a0, a0,  ra; bnez a0, error;"
        "ld      a0,  15*8(sp); sub a0, a0,  t0; bnez a0, error;"
        "ld      a0,  14*8(sp); sub a0, a0,  t1; bnez a0, error;"
        "ld      a0,  13*8(sp); sub a0, a0,  t2; bnez a0, error;"
        "ld      a0,  12*8(sp); sub a0, a0,  s0; bnez a0, error;"
        "ld      a0,  10*8(sp); sub a0, a0,  a1; bnez a0, error;"
        "ld      a0,   9*8(sp); sub a0, a0,  a2; bnez a0, error;"
        "ld      a0,   8*8(sp); sub a0, a0,  a3; bnez a0, error;"
        "ld      a0,   7*8(sp); sub a0, a0,  a4; bnez a0, error;"
        "ld      a0,   6*8(sp); sub a0, a0,  a5; bnez a0, error;"
        "ld      a0,   5*8(sp); sub a0, a0,  a6; bnez a0, error;"
        "ld      a0,   3*8(sp); sub a0, a0,  t3; bnez a0, error;"
        "ld      a0,   2*8(sp); sub a0, a0,  t4; bnez a0, error;"
        "ld      a0,   1*8(sp); sub a0, a0,  t5; bnez a0, error;"
        "ld      a0,   0*8(sp); sub a0, a0,  t6; bnez a0, error;"



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
        : /*input*/ [_syscall_nr] "i"(__NR_getpid)
    );
}
