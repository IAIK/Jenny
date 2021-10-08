#pragma once

#ifdef __x86_64__
#else
#error "Unsupported platform"
#endif //__x86_64__

#include "pk_arch.h"


#define INDIRECT_CALL_OFFSET 0x280

/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include "pk_debug.h"

#ifdef __cplusplus
extern "C" {
#endif

//extern uint64_t _pk_scratch;
extern void* _pk_syscall_handler_ptr;
extern uint64_t _pk_ttls_offset;

//------------------------------------------------------------------------------
// Internal definitions
//------------------------------------------------------------------------------

// internal pku functions
void _pk_sa_sigaction_asm(/*sig, info, ucontext*/);

// internal functions
void     PK_CODE _pk_exception_handler(void);
void     PK_CODE _pk_syscall_handler(void);
void     PK_CODE _pk_signal_handler(void);
void     PK_CODE _pk_exception_syscall(void);
void     PK_CODE _pk_exception_handler_end(void);
uint64_t PK_CODE _pk_exception_handler_arch_c(uint64_t id, uint64_t type);
int      PK_CODE _pk_init_arch();
void     PK_CODE _pk_setup_exception_stack_arch(void* exception_handler_stack);
void     PK_CODE _pk_setup_exception_handler_arch();
pkru_config_t PK_CODE _pk_create_default_config_arch(int did);
void     PK_CODE _pk_domain_switch_arch(int type, int target_did, pkru_config_t config, void* entry_point, uint64_t* target_stack);
int      PK_CODE _pk_domain_load_key_arch(int did, pkey_t pkey, int slot, int perm);
void*    PK_CODE _pthread_init_function_asm(void *arg);
void     PK_CODE _pk_assert_c(uintptr_t * assert_stack);

#define CURRENT_DID ({assert_ifdebug(DID_INVALID != pk_trusted_tls.current_did); assert_ifdebug(pk_trusted_tls.init); pk_trusted_tls.current_did;})

#ifdef __cplusplus
}
#endif

/**********************************************************************/
// For ASM only
#elif defined __ASSEMBLY__
/**********************************************************************/


#endif // defined __ASSEMBLY__
