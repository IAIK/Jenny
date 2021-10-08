#pragma once

// Max. number of foreign domains that can invoke current domain
#define NUM_SOURCE_DOMAINS 16

// Max. number of keys a domain can hold
// TODO: optimize to lower value
#define NUM_KEYS_PER_DOMAIN 2048

// Max. number of domains
#define NUM_DOMAINS 256
#define NUM_THREADS 256

#define NUM_PRIVATE_FILES 1

// Max. number of distinct contiguous memory regions pk can track
// TODO: optimize to lower value
#define NUM_MPROTECT_RANGES 4096

#define NUM_DOMAIN_FILTERS 440 //TODO: might be different size per architecture. Shift to arch code

#ifndef __ASSEMBLY__

// Internal PK code
#define PK_CODE __attribute__((section(".pk"),used))
#define PK_CODE_INLINE __attribute__((always_inline)) static inline PK_CODE
//#define PK_CODE_INLINE static inline PK_CODE
// Internal PK data
#define PK_DATA __attribute__((section(".pk_data"),used))
// PK code/data that is exported via shared library
#define PK_API  __attribute__ ((visibility ("default")))


// Some functions are used in both, trusted and untrusted code.
// FORCE_INLINE will inline them in the corresponding sections.
//
// If the compiler for some reason decides not to inline, the function
// will be placed in a dead section, and the linker will fail
#define FORCE_INLINE __attribute__((always_inline)) __attribute__((section(".deadcode"))) static inline

#endif /* __ASSEMBLY__ */

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

// ARCH needs to define PAGESIZE
#define PAGEMASK ((uintptr_t)(PAGESIZE-1))

#define ROUNDUP(x,base)   (((uintptr_t)(x) + ((uintptr_t)(base)-1)) & ~((uintptr_t)(base)-1))
#define ROUNDDOWN(x,base) ((uintptr_t)(x) & ~((uintptr_t)(base)-1))

#define ROUNDUP_PAGE(x)   ROUNDUP(x, PAGESIZE)
#define ROUNDDOWN_PAGE(x) ROUNDDOWN(x, PAGESIZE)
