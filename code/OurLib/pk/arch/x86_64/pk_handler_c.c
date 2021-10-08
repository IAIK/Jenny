#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include "pk_internal.h"

PK_DATA void* _pk_syscall_handler_ptr = NULL;

#ifdef FAKE_MPK_REGISTER

// should be thread-local, but since this is for emulation only, we don't care
pkru_config_t PK_API emulated_mpk_reg = {0,};

#endif

/**
 * Per-thread trusted storage
 *
 * It has the following properties
 * - placed inside TLS at a fixed offset
 * - the offset is computed during initialization, and stored in tls_trusted_offset
 * - protected dynamically in the same way as PK_DATA for static variables
 *   Thus, it needs to be aligned on a page boundary, and be multiples of a page size
 * - Access only via TLS macro
 */

//------------------------------------------------------------------------------
// Public API functions
//------------------------------------------------------------------------------
int PK_CODE _pk_init_arch() {
    DEBUG_MPK("_pk_init_arch");

    // needed for sysfilter
    _write_pkru_reg(0x0);
    DEBUG_MPK("Handler pkru-reg = 0x%lx", _read_pkru_reg());
    DEBUG_MPK("User pkru-reg (will be set when leaving pk handler) = 0x%lx", read_pkru_current_thread(pk_trusted_tls.current_did));

    assert(pk_trusted_tls.current_did == DID_FOR_ROOT_DOMAIN ||
           pk_trusted_tls.current_did == DID_FOR_CHILD_DOMAIN);

    return 0;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// Internal functions
//------------------------------------------------------------------------------

void PK_CODE _prepare_pkru_swap_c() {
    //~ pk_trusted_rotls.asm_pkru = read_pkru_current_thread(CURRENT_DID);
    if (pk_trusted_tls.signal_state == SIGNAL_RESUME) {
        pk_trusted_rotls.asm_pkru = 0; // keep full monitor permissions
        pk_trusted_tls.signal_state = SIGNAL_NONE;
    } else {
        pk_trusted_rotls.asm_pkru = read_pkru_current_thread(CURRENT_DID);
    }
}
//------------------------------------------------------------------------------

void PK_CODE _pk_setup_exception_stack_arch(void* exception_stack) {
    // -2 because (in x86_64) the stack must be 16-byte aligned for psabi
    pk_trusted_tls.exception_stack_base = exception_stack;
    pk_trusted_tls.exception_stack = pk_trusted_tls.exception_stack_base + EXCEPTION_STACK_WORDS - 2;
    DEBUG_MPK("_pk_setup_exception_stack(%p)", exception_stack);

    if (pk_data.initialized) {
      assert(_pk_ttls_offset == (uint64_t)&pk_trusted_tls.backup_user_stack - (uint64_t)_get_fsbase());
    }

    DEBUG_MPK("backup_user_stack    = %p", pk_trusted_tls.backup_user_stack);
    DEBUG_MPK("exception_stack_top  = %p", pk_trusted_tls.exception_stack);
    DEBUG_MPK("exception_stack_base = %p", pk_trusted_tls.exception_stack_base);
}
//------------------------------------------------------------------------------

void PK_CODE _pk_setup_exception_handler_arch() {
}
//------------------------------------------------------------------------------

pkru_config_t PK_CODE _pk_create_default_config_arch(int did) {

    pkru_config_t config = ((pkru_config_t)-1) << 2; // Deny all access except for KEY_FOR_UNPROTECTED
    config &= 0xFFFFFFFF; //pkru can only handle 32bit

    for (size_t kid = 0; kid < NUM_KEYS_PER_DOMAIN; kid++) {
        pk_key_t key = pk_data.domains[did].keys[kid];
        if (!key.used) {
            continue;
        }
        DEBUG_MPK("Domain setting key %d perm %d", key.pkey, key.perm);
        pkru_config_t nkey       =                                   (pkru_config_t)key.perm << (key.pkey*2);
        const pkru_config_t mask = (pkru_config_t)(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE) << (key.pkey*2);
        config &= (nkey | ~mask);
    }

    DEBUG_MPK("Domain %d: pkru config is 0x%lx", did, config);

    return config;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_load_key_arch(int did, pkey_t pkey, int slot, int perm) {
    if (slot != PK_SLOT_ANY && slot != PK_SLOT_NONE) {
        ERROR("Invalid slots");
        errno = EINVAL;
        return -1;
    }

    if ((int)pkey < 0 || pkey >= PK_NUM_KEYS) {
        ERROR("Invalid pkey %d. Must be between 0 and 15", pkey);
        errno = EINVAL;
        return -1;
    }

    if (PK_SLOT_NONE == slot) {
        // By disabling access, key is unloaded in x86
        perm = PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE;
    }

    if (perm & ~(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE)) {
        ERROR("Invalid permissions. Only supports PKEY_DISABLE_ACCESS and PKEY_DISABLE_WRITE");
        errno = EINVAL;
        return -1;
    }

    // PKRU layout:
    // AD: access (read+write) disabled
    // WD: write disabled
    // 31                       1 0  bit position
    // |W|A|W|A|...|W|A|W|A|W|A|W|A|
    // |D|D|D|D|...|D|D|D|D|D|D|D|D|
    // |f|f|e|e|...|3|3|2|2|1|1|0|0|

    pkru_config_t pkru = read_pkru_current_thread(did);
    pkru_config_t nkey       =                                       (pkru_config_t)perm << (pkey*2);
    const pkru_config_t mask = (pkru_config_t)(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE) << (pkey*2);
    DEBUG_MPK("Old register: 0x%lx", pkru);

    // apply new key to corresponding slots
    //DEBUG_MPK("Mask          0x%lx", mask);
    //DEBUG_MPK("Nkey          0x%lx", nkey);
    pkru &= ~mask;
    pkru |= nkey;

    DEBUG_MPK("New register: 0x%lx", pkru);

    //update config
    write_pkru_current_thread(did, pkru);

    return 0;
}
//------------------------------------------------------------------------------

// Ensure that _expected_return stack is not 16-byte but 8-byte aligned
// This ensures that user stack gets 16-byte aligned for psabi
// See _pk_exception_handler_arch_c
C_STATIC_ASSERT((sizeof(_expected_return) % 16) == 8);
C_STATIC_ASSERT((sizeof(_return_did)      % 16) == 8);


uint64_t PK_CODE _pk_exception_handler_arch_c(uint64_t type, uint64_t id){
#ifdef TIMING
    TIME_START(TIMING_HANDLER_C);
#endif
    _pk_acquire_lock();

    void * reentry = 0;
    // user stack is still misaligned by 8 bytes. _pk_exception_handler_c
    // pushes _expected_return struct on user stack s.t. it becomes
    // 16-byte aligned
    DEBUG_MPK("_pk_exception_handler_arch_c: stack=%p", pk_trusted_tls.backup_user_stack);

    if (type == TYPE_CALL) {
        assert_ifdebug(((uintptr_t)pk_trusted_tls.backup_user_stack % 16) == 8); // check stack misaligned
        reentry = (void*)*(pk_trusted_tls.backup_user_stack); // get original reentry point
    }else{
        assert_ifdebug(((uintptr_t)pk_trusted_tls.backup_user_stack % 16) == 0); // check stack misaligned
    }

    uint64_t ret = _pk_exception_handler_unlocked(0, id, type, pk_trusted_tls.backup_user_stack, reentry);

    _pk_release_lock();
#ifdef TIMING
    TIME_STOP(TIMING_HANDLER_C);
#endif
    return ret;
}
//------------------------------------------------------------------------------

void PK_CODE _pk_domain_switch_arch(int type, int target_did, pkru_config_t config, void* entry_point, uint64_t* target_stack) {
    DEBUG_MPK("_pk_domain_switch_arch(%d, %d, 0x%lx, %p, %p)", type, target_did, config, entry_point, target_stack);

    // config is switched in Assembler code via asm wrpkru(tls.asm_pkru), which is set in _pk_domain_switch

    // Switch to target stack
    pk_trusted_tls.backup_user_stack = target_stack;

    // Switch to target did
    pk_trusted_tls.current_did = target_did;

    // For TYPE_RET, the original reentry point is already pushed on the
    // original caller's stack (target stack). For TYPE_CALL, we need to
    // push the entry point on the target stack manually.
    // This allows to use the 'ret' instruction (in return_from_exception)
    if (type == TYPE_CALL || type == TYPE_SYSCALL_FILTER || type == TYPE_SIGNAL_ENTER) {
        assert_ifdebug(((uintptr_t)pk_trusted_tls.backup_user_stack % 16) == 8);

        pk_trusted_tls.backup_user_stack--;
        *(pk_trusted_tls.backup_user_stack) = (uint64_t)entry_point;

        // Our ecall_receive wrapper and the syscall filter are normal functions
        // I.e. the call site has an aligned stack, and the callee site expects a
        // misaligned stack.
        // Hence, we must be aligned s.t. return_from_exception (the ret instruction)
        // misaligns it when entering the callee site
        assert_ifdebug(((uintptr_t)pk_trusted_tls.backup_user_stack % 16) == 0);
    } else if (type == TYPE_SYSCALL_RET) {
        // The syscall callee site also expects a misaligned stack. However,
        // since the syscall instruction itself does not push data on the stack,
        // the syscall call site also has a misaligned stack (unlike a normal function call).
        // Hence, we must be aligned s.t. return_from_exception misaligns it again when
        // returning to the call site.
        assert_ifdebug(((uintptr_t)pk_trusted_tls.backup_user_stack % 16) == 0);
    } else if (type == TYPE_RET) {
        // ecalls are like normal function calls, where the call site is aligned.
        // Hence, we must be misaligned s.t. return_from_exception aligns it again
        // when returning to the call site.
        assert_ifdebug(((uintptr_t)pk_trusted_tls.backup_user_stack % 16) == 8);
    } else if (type == TYPE_SIGNAL_RET) {
        pk_trusted_tls.backup_user_stack--;
        *(pk_trusted_tls.backup_user_stack) = (uint64_t)entry_point;
        // No stack alignment check here, as the signal could have been fired anywhere
    } else if (type == TYPE_SIGNAL_RETMONITOR) {
        // Do nothing
    } else {
        assert_ifdebug(false);
    }
    assert_ifdebug(_pk_current_did() == target_did);
}
//------------------------------------------------------------------------------

void PK_CODE __attribute__((naked)) _pk_pthread_exit(void* retval) {
  __asm__ volatile(
    "push %rdi\n"                   //save retval (also ensures proper psabi alignment)
    "call _pk_pthread_exit_c\n"     // _pk_domain_switch to pthread_exit
    "pop %rdi\n"                    // restore retval as first argument (rdi) for pthread_exit after domain switch
    "ret\n"
  );
}
//------------------------------------------------------------------------------

void __attribute__((naked)) _pthread_exit_asm()
{
    __asm__ volatile(
        "add $-8, %%rsp\n"         // psabi alignment
        "mov %%rax, %%rdi\n"       // propagating return value of thread (rax) to argument (rdi) for API call
        "call pk_pthread_exit\n"   // API call
        "ud2"                      // unreachable
        : : : "rdi"
    );
}

void* PK_CODE __attribute__((naked)) _pthread_init_function_asm(void * arg) {
  // We're entering here with the new user stack but in trusted mode
  // switch to trusted exception stack and call into C wrapper
  __asm__ volatile(
    "mov %[start_routine],   %%rdi\n"  // save start_routine as first argument
    "mov %[thread_exit],   (%%rsp)\n"  // overwriting libc return address
    "mov %%rsp,              %%rsi\n"  // save current_user_stack as second argument
    "mov %[exception_stack], %%rsp\n"  // load exception stack
    "mov %[_arg],            %%rbx\n"  // load *arg for start_routine in callee-saved register (rbx)
    "call _pthread_init_function_c\n"
    "mov %%rbx, %%rdi\n"               // load *arg as first argument for start_routine
    "jmp " S_PIC(_pk_exception_handler_end) "\n"
    : // no output operands
    : [start_routine]   "m"(pk_data.pthread_arg.start_routine),
      [thread_exit]     "r"(_pthread_exit_asm),
      [exception_stack] "m"(pk_data.pthread_arg.exception_stack_top),
      [_arg]            "m"(pk_data.pthread_arg.arg)
      //Clobber list ensures that we're using callee-saved registers for input arguments.
      //This is important since the input argument locations are resolved before the call
    : "rdi", "rsi", "rbx",
      /*"rbx",*/"rsp","rbp","r12","r13","r14","r15" // + all caller-saved registers
  );
}
//------------------------------------------------------------------------------

enum {
  rsp=0,
  rbp,
  rax,
  rbx,
  rcx,
  rdx,
  rsi,
  rdi,
  r8,
  r9,
  r10,
  r11,
  r12,
  r13,
  r14,
  r15,
#ifndef FAKE_MPK_REGISTER
  pkru,
#endif
  rend
};

#define _GET_VAL(r, stack) ((stack)[rend-1-(r)])
#define PRINT_REG(r, stack) ERROR("%4s: 0x%016lx = %ld", #r, _GET_VAL(r, stack), _GET_VAL(r, stack))

void PK_CODE __attribute__((noreturn)) _pk_assert_c(uintptr_t * assert_stack) {
    ERROR("_pk_assert_c DYING");
    PRINT_REG(rsp, assert_stack);
    PRINT_REG(rbp, assert_stack);
    PRINT_REG(rax, assert_stack);
    PRINT_REG(rbx, assert_stack);
    PRINT_REG(rcx, assert_stack);
    PRINT_REG(rdx, assert_stack);
    PRINT_REG(rsi, assert_stack);
    PRINT_REG(rdi, assert_stack);
    PRINT_REG(r8 , assert_stack);
    PRINT_REG(r9 , assert_stack);
    PRINT_REG(r10, assert_stack);
    PRINT_REG(r11, assert_stack);
    PRINT_REG(r12, assert_stack);
    PRINT_REG(r13, assert_stack);
    PRINT_REG(r14, assert_stack);
    PRINT_REG(r15, assert_stack);
#ifndef FAKE_MPK_REGISTER
    PRINT_REG(pkru, assert_stack);
#endif
    ERROR("Additional info (maybe line number in pk_handler.S):");
    PRINT_REG(-1, assert_stack); // info pushed by ASSERT_WITH_INFO
    assert(false);
}
//------------------------------------------------------------------------------

