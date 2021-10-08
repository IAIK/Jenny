#pragma once
#include <stdint.h>
#include <stddef.h>
#include <linux/mman.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


struct dtv_pointer
{
    void *val;                    /* Pointer to data, or TLS_DTV_UNALLOCATED.  */
    void *to_free;                /* Unaligned pointer, for deallocation.  */
};

/* Type for the dtv.  */
typedef union dtv
{
    size_t counter;
    struct dtv_pointer pointer;
} dtv_t;

typedef struct
{
    void *tcb;                /* Pointer to the TCB.  Not necessarily the
                                                     thread descriptor used by libpthread.  */
    dtv_t *dtv;
    void *self;                /* Pointer to the thread descriptor.  */
    int multiple_threads;
    int gscope_flag;
    uintptr_t sysinfo;
    uintptr_t stack_guard;
    uintptr_t pointer_guard;
    unsigned long int vgetcpu_cache[2];
    /* Bit 0: X86_FEATURE_1_IBT.
         Bit 1: X86_FEATURE_1_SHSTK.
     */
    unsigned int feature_1;
    int __glibc_unused1;
    /* Reservation of some values for the TM ABI.  */
    void *__private_tm[4];
    /* GCC split stack support.  */
    void *__private_ss;
    /* The lowest address of shadow stack,  */
    unsigned long long int ssp_base;
    /* Must be kept even if it is no longer used by glibc since programs,
         like AddressSanitizer, depend on the size of tcbhead_t.  */
    __int128 __glibc_unused2[8][4] __attribute__ ((aligned (32)));
    void *__padding[8];
} tcbhead_t;

typedef struct list_head
{
  struct list_head *next;
  struct list_head *prev;
} list_t;

/* reduced interface */
struct pthread
{
  union {
    tcbhead_t header;
    void *__padding[24];
  };
  /* This descriptor's link on the `stack_used' or `__stack_user' list.  */
  list_t list;

  /* Thread ID - which is also a 'is this thread descriptor (and
  therefore stack) used' flag.  */
  pid_t tid;
};