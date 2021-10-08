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
  dtv_t *dtv;
  void *private;
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