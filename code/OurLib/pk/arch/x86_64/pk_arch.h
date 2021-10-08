#pragma once
#include "pk_defs.h"
#include "mprotect.h"
#include "pk_debug.h"

//------------------------------------------------------------------------------
// Arch-specific API definitions
//------------------------------------------------------------------------------

#define WORDSIZE 8
#define PAGESIZE 4096
#define PK_NUM_KEYS 16

// PK handler types
// Do not change these values, as asm code would break!
#define TYPE_RET  0
#define TYPE_CALL 1
#define TYPE_API  2
#define TYPE_SYSCALL_RET 3
#define TYPE_EXCEPTION 4
#define TYPE_SYSCALL_FILTER 5
#define TYPE_SIGNAL_ENTER 6
#define TYPE_SIGNAL_RET 7
#define TYPE_SIGNAL_RETMONITOR 8

// Type distinguishes dcalls, returns and API calls
#define rdi_type %rdi
// Holds the ID of a dcall
#define rsi_id   %rsi

#ifdef SHARED

// To access global variables directly from assembler code,
// they must be marked __attribute__((visibility("hidden"))). 
// Otherwise, they are globally exported and require GOT.
// We avoid this via CFLAGS=-fvisibility=hidden

// Intra-lib data access
#define PIC(x) x(%rip)
// Cross-library function calls
#define PLT(x) x@plt
// Intra-lib function calls
#define PCREL(x) x
// String-representation of PIC, for C-inline assembler
// We did not manage to make _pk_exception_handler_end "hidden", so
// use plt indirection instead
#define S_PIC(x) #x"@plt"

#else // SHARED=0 (STATIC)

#define PIC(x) x
#define PLT(x) x
#define PCREL(x) x
#define S_PIC(x) #x

// Immediate relocation for fs-relative access
// E.g.:
//      movq $1, fs:(TTLS(FILTER_SYSCALLS))
// This only works for static library (local-exec model)
#define TTLS(member) (pk_trusted_tls@tpoff + TTLS_OFFSET_##member)

#endif // SHARED

// Load address of TTLS member into reg
// E.g.:
//      LOAD_TTLS_ADDRESS(FILTER_SYSCALLS, %rax)
//      movq $1, fs:(%rax)
// This also works for shared library (initial-exec model)
#define LOAD_TTLS_ADDRESS(member, reg) \
  movq pk_trusted_tls@gottpoff(%rip), reg; \
  addq $(TTLS_OFFSET_##member), reg

#define LOAD_ROTTLS_ADDRESS(member, reg) \
  movq pk_trusted_tls@gottpoff(%rip), reg; \
  addq $(ROTTLS_OFFSET_##member), reg
  
/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t pkey_t;
typedef uint64_t pkru_config_t;

#define GET_TLS_POINTER ((uintptr_t)_get_fsbase())

FORCE_INLINE uint64_t _get_fsbase() {
    uint64_t ret;
    __asm__ volatile ("mov %%fs:0x0, %0" : "=r" (ret));
    return ret;
}

#define PKRU_TO_INT(x) (x)
#define INT_TO_PKRU(x) (x)

#ifdef FAKE_MPK_REGISTER

extern pkru_config_t emulated_mpk_reg;

FORCE_INLINE pkru_config_t _read_pkru_reg() {
    pkru_config_t copy = emulated_mpk_reg;
    return copy;
}

FORCE_INLINE void _write_pkru_reg(pkru_config_t new_config) {
    emulated_mpk_reg = new_config;
}

#else /* FAKE_MPK_REGISTER */

FORCE_INLINE pkru_config_t _read_pkru_reg() {
    pkru_config_t ret;
    // https://www.felixcloutier.com/x86/rdpkru
    __asm__ volatile(
      "xor %%ecx, %%ecx\n"
      "rdpkru"
      : "=a"(ret)
      : /* no inputs */
      : "rdx"
    );
    return ret;
}

FORCE_INLINE void _write_pkru_reg(pkru_config_t new_val) {
    // https://www.felixcloutier.com/x86/wrpkru
    __asm__ volatile(
      "xor %%ecx, %%ecx\n" // clear ecx
      "xor %%edx, %%edx\n" // clear edx
      "wrpkru"
      : /* no outputs */
      : "a"(new_val)
      : "rcx", "rdx"
    );
}

#endif /* FAKE_MPK_REGISTER */

FORCE_INLINE void pk_debug_usercheck_arch() {
}

//------------------------------------------------------------------------------

#define _pk_is_pkey_loaded_arch(pkey, pkru) ({ \
    const pkru_config_t mask = (pkru_config_t)(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE) << (pkey*2); \
    bool _ret = ((pkru & mask) != mask); \
    _ret; \
})

//------------------------------------------------------------------------------


#ifdef CUSTOM_MEMCPY

FORCE_INLINE void* pk_memcpy(void* dst, const void *src, size_t n) {
   char *psrc = (char*)src;
   char *pdst = (char*)dst;
  
   for (size_t i = 0; i < n; i++) {
       pdst[i] = psrc[i];
   }
   return dst;
}

#else
#define pk_memcpy memcpy
#endif

//------------------------------------------------------------------------------

#include <stdio.h>
FORCE_INLINE char * pk_sprint_reg_arch(pkru_config_t reg){
    static char buf[256];
    int len = 0;
    len += sprintf(buf+len, "0x%16lx, ", reg);
    for (int pkey = 15; pkey >= 0; pkey--)
    {
        const unsigned int disable_access = (reg >> (pkey*2)) & PKEY_DISABLE_ACCESS;
        const unsigned int disable_write  = (reg >> (pkey*2)) & PKEY_DISABLE_WRITE;
        //const unsigned int mask = (unsigned int)(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE) << (pkey*2);
        len += sprintf(buf+len, "%d:%s ", 
            pkey,
            disable_access ? "-" : (disable_write ? COLOR_GREEN"r"COLOR_RESET : COLOR_YELLOW"w"COLOR_RESET)
        );
    }
    assert((size_t)len < sizeof(buf));
    return buf;
}
FORCE_INLINE void pk_print_reg_arch(pkru_config_t reg){
    FPRINTF(stderr, "%s\n", pk_sprint_reg_arch(reg));
}
//------------------------------------------------------------------------------

struct trace_info_t;
void     _sf_domain_syscall_handler(struct trace_info_t *ti);
void     _pk_signal_handler_domain();

// x86 does not need to store syscall reentry, since we keep it on the user stack
// Set it to a non-zero value
#define SYSCALL_REENTRY ((void*)(uintptr_t)-1)
#define SYSCALL_STACK (pk_trusted_tls.backup_user_stack)


//Note that RSP is also callee-saved, but the exception handler handles its preservation
#define SAVE_CALLEE_REGS_INLINE_ASM "push %%rbp; push %%r15; push %%r14; push %%r13; push %%r12; push %%rbx; add $-0x8, %%rsp;"
#define RESTORE_CALLEE_REGS_INLINE_ASM "add $0x8, %%rsp;  pop %%rbx;  pop %%r12;  pop %%r13;  pop %%r14;  pop %%r15;  pop %%rbp;"

#define TRIGGER_EXCEPTION_INLINE_ASM "call "S_PIC(pk_exception_handler)";"

#define ECALL(...) ecall_##__VA_ARGS__

#define _ECALL_RECEIVE_INLINE_ASM(ecall_id, FUNCTION_NAME) \
    __asm__ volatile( \
        "add $-0x8, %%rsp;" \
        "call "#FUNCTION_NAME";" \
        "mov %[_type], %%rdi;" \
        "mov %[_id], %%rsi;" \
        "add $0x8, %%rsp;" \
        TRIGGER_EXCEPTION_INLINE_ASM \
        "jmp .;" \
        : \
        : [_type] "i"(TYPE_RET), \
            [_id] "m"(ecall_id) \
    );

#define _ECALL_INLINE_ASM(ecall_id) \
    __asm__ volatile( \
        SAVE_CALLEE_REGS_INLINE_ASM \
        "push %%rdi;" \
        "push %%rsi;" \
        "mov %[_type], %%rdi;" \
        "mov %[_id], %%rsi;" \
        TRIGGER_EXCEPTION_INLINE_ASM \
        "add $16, %%rsp;" \
        RESTORE_CALLEE_REGS_INLINE_ASM \
        "ret;" \
        :  \
        : [_type] "i"(TYPE_CALL), \
            [_id] "m"(ecall_id) \
    );

#define PK_ECALL_REGISTER(name, did) ({ ecall_id_##name = pk_domain_register_ecall3(did, PK_ECALL_ANY, _ecall_receive_##name, #name); ecall_id_##name; })

#define GEN_ALL(name, return_type, ...) \
    static int64_t ecall_id_##name = 0; \
    \
    void __attribute__((naked)) _ecall_receive_##name() { \
        _ECALL_RECEIVE_INLINE_ASM(ecall_id_##name, name) \
    } \
    \
    return_type __attribute__((naked)) ecall_##name(__VA_ARGS__) { \
        _ECALL_INLINE_ASM(ecall_id_##name) \
    } \
    \
    /*int ecall_register_##name(int did){*/\
    /*    ecall_id_##name = pk_domain_register_ecall2(did, PK_ECALL_ANY, _ecall_receive_##name);*/\
    /*    return ecall_id_##name;*/\
    /*}*/

#ifdef __cplusplus
}
#endif

/**********************************************************************/
// For ASM only
#elif defined __ASSEMBLY__
/**********************************************************************/

.macro trigger_exception
    call PLT(pk_exception_handler) // Since first call invokes the dynamic linker, which manipulates r10, we use LD_BIND_NOW=1
.endm

.macro return_from_exception
    ret
.endm

.macro DIE
    jmp .
.endm

.macro SAVE_CALLEE_REGS
    push %rbp
    push %r15
    push %r14
    push %r13
    push %r12
    push %rbx
    add $-0x8, %rsp // to avoid psabi misalignment, we need an odd number
                    // of pushes
    //Note that RSP is also callee-saved, but the exception handler handles its preservation
.endm

.macro RESTORE_CALLEE_REGS
    add $0x8, %rsp // to avoid psabi misalignment
    pop %rbx
    pop %r12
    pop %r13
    pop %r14
    pop %r15
    pop %rbp
.endm

/**
 * Macro for generating call wrappers
 * @param name Name of the generated wrapper function
 * @param id   Unique integer of the wrapped function
 * @param type TYPE_ECALL or TYPE_API
 */
.macro GEN_CALL_WRAPPER name id
.global ecall_\name
.type ecall_\name @function
ecall_\name:

    // Save callee regs since we cannot rely on potentially untrusted
    // ecall target to behave properly
    SAVE_CALLEE_REGS

    // Save first two argument registers on stack since we replace them
    // with type and call id
    push rdi_type
    push rsi_id

    mov $(TYPE_CALL),   rdi_type
    mov $(\id),         rsi_id

    trigger_exception
_reentry_\name:

    // Cleanup stack
    add $16, %rsp

    RESTORE_CALLEE_REGS
    ret
.endm

/**
 * Macro for generating return wrappers
 * @param name Name of the function. The wrapper will invoke _name
 * @param id   Unique integer of the wrapped function
 */
.macro GEN_CALLEE_WRAPPER name id
.global _ecall_receive_\name
_ecall_receive_\name:

    add $-0x8, %rsp      // to avoid psabi misalignment
    call \name

    mov $(TYPE_RET), rdi_type
    mov $(\id),      rsi_id

    add $0x8, %rsp      // to avoid psabi misalignment
    trigger_exception
    DIE
.endm

/**
 * Macro for generating register wrappers
 * @param name Name of the function to be registered.
 * @param id   Unique integer of the wrapped function
 */
.macro GEN_REGISTER name id
.global ecall_register_\name
.type ecall_register_\name @function
ecall_register_\name:

    // _pk_domain_register_ecall2(int did, uint id, void * entry_point)
    // rdi = did
    // rsi = id
    // rdx = entry_point
    //mov      %rdi, %rdi
    mov      $(\id), %rsi
    lea      PIC(_ecall_receive_\name), %rdx

    jmp pk_domain_register_ecall2
    DIE
ret
.endm

.macro GEN_ALL_SIMPLE name id
    GEN_REGISTER       \name \id
    GEN_CALL_WRAPPER   \name \id
    GEN_CALLEE_WRAPPER \name \id
.endm


/**
 * Macro for generating API call wrappers
 * @param name Name of the generated wrapper function
 * @param id   Unique integer of the wrapped function
 * @param type TYPE_ECALL or TYPE_API
 */
.macro GEN_CALL_WRAPPER_API name id
.global \name
.type \name @function
\name:
    // Unlike GEN_CALL_WRAPPER, we do not need to save callee registers
    // since we assume that the trusted handler follows calling convention

    // Save first two argument registers on stack since we replace them
    // with type and call id
    push rdi_type
    push rsi_id

    mov $(TYPE_API),    rdi_type
    mov $(\id),         rsi_id

    trigger_exception

_reentry_\name:
    // Cleanup stack
    add $16, %rsp
    ret
.endm

/**
 * Macro for generating call wrappers that fall back to the libc function
 * if not initialized yet (i.e. pk_initialized is false)
 * 
 * @param name points to the original libc function. The generated wrapper
 *             function gets a pk_ prefix.
 * @param id   Unique integer of the wrapped function
 * @param type TYPE_ECALL or TYPE_API
 */
.macro GEN_CALL_WRAPPER_API_FALLBACK name id
.global pk_\name
.type pk_\name @function
pk_\name:
    // If pk is not initialized yet, call the native function
    movzb PIC(pk_initialized), %r10
    test %r10, %r10
    jne 1f
#ifdef DLU_HOOKING
    // If preloading is active, we need to call the hopefully already resolved real-function
    lea PIC(real_\name), %r10
    jmp *(%r10)
#else
    // No preloading - we can directly invoke the original libc/pthread function
    jz PLT(\name)
#endif
1:
    GEN_CALL_WRAPPER_API pk2_\name \id
.endm

#endif // __ASSEMBLY__
