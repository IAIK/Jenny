#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "test2_ecall.h"
#include "test3_ecall.h"
#include "pk.h"
#include "pk_debug.h"


int test_function(int arg){
    assert(arg);
    return arg;
}
GEN_ALL(test_function, int, int arg);

void test3_init(int target_domain){
    int ret = PK_ECALL_REGISTER(test_function, target_domain);
    assert(ret >= 0);
}

extern int test2_domain;
void test3() {
    //Reading private data (should fail if not called via ecall_test3)
    uint64_t * x = (uint64_t*)&test3;
    printf("test3: %lx\n", *x);

    pk_print_current_reg();

    printf("test3: Calling test2 ecall function:\n");
    uint64_t ret = ecall_test_args(0x10, 0x11, 0x12, 0x13, 0x14, 0x15);
    printf("ecall_test_args returned %lx\n", ret);
    assert(ret == 0xAABBCCDD00112233ULL);

    printf("test3: Calling test2 ecall function which then calls api functions:\n");
    ecall_test_api_calls();

    int ret2;
    //ret2 = PK_ECALL_REGISTER(test_function, test2_domain);
    //printf("registered ecall: %d\n", ret2);
    //assert(ret2 >= 0);
    ret2 = ECALL(test_function(1234));
    assert(ret2 == 1234);
    ret2 = ECALL(test_function(1234));
    assert(ret2 == 1234);


}

int test3_nested(int arg){
    DEBUG_MPK("test3_nested(%d)", arg);
    //pk_print_current_reg();
    arg--;
    if(arg > 0){
        DEBUG_MPK("test3_nested: Calling ecall_test2_nested(%d)\n", arg);
        int ret = ecall_test2_nested(arg);
        DEBUG_MPK("test3_nested: Successfully called ecall_test2_nested(%d). return value was %d\n", arg, ret);
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

uint64_t test3_time(){
    return RDTSC();
}
