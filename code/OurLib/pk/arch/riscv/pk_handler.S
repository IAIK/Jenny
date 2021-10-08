#define __ASSEMBLY__
#include "pk_internal.h"

#include "pku_api_wrapper.S"

# ------------------------------------------------------------------------------
//Note: FRAMESIZE should/must be a multiple of 128-bit
#define FRAMESIZE           (20 * 8)
#define OFFSET_ra           (19 * 8)
#define OFFSET_t0           (18 * 8)
#define OFFSET_t1           (17 * 8)
#define OFFSET_t2           (16 * 8)
#define OFFSET_s0           (15 * 8)
#define OFFSET_a0           (14 * 8)
#define OFFSET_a1           (13 * 8)
#define OFFSET_a2           (12 * 8)
#define OFFSET_a3           (11 * 8)
#define OFFSET_a4           (10 * 8)
#define OFFSET_a5           ( 9 * 8)
#define OFFSET_a6           ( 8 * 8)
#define OFFSET_a7           ( 7 * 8)
#define OFFSET_t3           ( 6 * 8)
#define OFFSET_t4           ( 5 * 8)
#define OFFSET_t5           ( 4 * 8)
#define OFFSET_t6           ( 3 * 8)
#define OFFSET_s1           ( 2 * 8) //used for syscall stuff
#define OFFSET_cookie       ( 1 * 8)
#define OFFSET_unused       ( 0 * 8)
#define OFFSET_reg_a2_type  OFFSET_a2

#ifndef RELEASE
#define INSTALL_COOKIE(CONSTANT) SAVE(a0); li a0, CONSTANT; sd a0, OFFSET_cookie(sp); RESTORE(a0);
#define CHECK_COOKIE(CONSTANT)   SAVE(a1); SAVE(a2); li a1, CONSTANT; ld a2, OFFSET_cookie(sp); bne a1, a2, fail; RESTORE(a1); RESTORE(a2);
#else
#define INSTALL_COOKIE(CONSTANT)
#define CHECK_COOKIE(CONSTANT)
#endif


#define SAVE(reg) sd reg, OFFSET_##reg (sp)
#define RESTORE(reg) ld reg, OFFSET_##reg (sp)
#define ALLOCATE_FRAME(CONSTANT) addi  sp, sp, -FRAMESIZE; INSTALL_COOKIE(CONSTANT);
#define DELETE_FRAME(CONSTANT) CHECK_COOKIE(CONSTANT); addi  sp, sp, FRAMESIZE

# ------------------------------------------------------------------------------

// we do not need to save: s1-11(callee saved) apart from s1 which we use in pk_handler.S
// syscall arguments (a0..a7) need to be saved since they're caller-saved and we call a C function
.macro SAVE_FRAME_SYS_HANDLER
    ALLOCATE_FRAME(0x1234ABCDEF)
    //Note we're using the same ALLOCATE_FRAME macro for syscalls, such that we can always use SAVE/RESTORE macros
    SAVE(s1)
    SAVE(ra)
    SAVE(t0)
    SAVE(t1)
    SAVE(t2)
    SAVE(s0)
    //SAVE(a0) // no need to save a0 -> it will later contain the return value
    SAVE(a1)
    SAVE(a2)
    SAVE(a3)
    SAVE(a4)
    SAVE(a5)
    SAVE(a6)
    SAVE(a7)
    SAVE(t3)
    SAVE(t4)
    SAVE(t5)
    SAVE(t6)
.endm

.macro RESTORE_FRAME_SYS_HANDLER
    RESTORE(s1)
    RESTORE(ra)
    RESTORE(t0)
    RESTORE(t1)
    RESTORE(t2)
    RESTORE(s0)
    //RESTORE(a0)  //a0 is the syscall return value and must not be restored
    RESTORE(a1)
    RESTORE(a2)
    RESTORE(a3)
    RESTORE(a4)
    RESTORE(a5)
    RESTORE(a6)
    RESTORE(a7)
    RESTORE(t3)
    RESTORE(t4)
    RESTORE(t5)
    RESTORE(t6)
    DELETE_FRAME(0x1234ABCDEF)
.endm

# ------------------------------------------------------------------------------
#ifndef RELEASE
.macro __ASSERT_WITH_INFO__ info
    j 2f
    1:
    li s0, \info
    la s1, _pk_assert_stack_top
    sd s0, -8(s1)
    j _pk_assert
    2:
.endm
.macro ASSERT_WITH_INFO0 info jump_ins
    \jump_ins 1f
    __ASSERT_WITH_INFO__ \info
.endm
.macro ASSERT_WITH_INFO1 info branch_ins branch_reg_1
    \branch_ins \branch_reg_1, 1f
    __ASSERT_WITH_INFO__ \info
.endm
.macro ASSERT_WITH_INFO2 info branch_ins branch_reg_1 branch_reg_2
    \branch_ins \branch_reg_1, \branch_reg_2, 1f
    __ASSERT_WITH_INFO__ \info
.endm
#else
.macro ASSERT_WITH_INFO0 info jump_ins
    \jump_ins _pk_assert
.endm
.macro ASSERT_WITH_INFO1 info branch_ins branch_reg_1
    \branch_ins \branch_reg_1, _pk_assert
.endm
.macro ASSERT_WITH_INFO2 info branch_ins branch_reg_1 branch_reg_2
    \branch_ins \branch_reg_1, \branch_reg_2, _pk_assert
.endm
#endif
# ------------------------------------------------------------------------------
.macro SET_FILTER_SYSCALLS reg_tmp1 reg_tmp2
    lui  \reg_tmp1, %tprel_hi(pk_trusted_tls)
    add  \reg_tmp1, \reg_tmp1, tp, %tprel_add(pk_trusted_tls)
    addi \reg_tmp1, \reg_tmp1, %tprel_lo(pk_trusted_tls)
    li   \reg_tmp2, TTLS_OFFSET_FILTER_SYSCALLS
    add  \reg_tmp1, \reg_tmp1, \reg_tmp2 //add offset to address

    /* cannot do these checks anymore
    #ifndef RELEASE
    //assert before set:
    ld   \reg_tmp2, 0(\reg_tmp1)
    //bne  \reg_tmp2, zero, fail
    ASSERT_WITH_INFO2 __LINE__ beq  \reg_tmp2 zero
    #endif
    */

    //set value
    addi \reg_tmp2, zero, 1
    sd   \reg_tmp2, 0(\reg_tmp1)
.endm
.macro UNSET_FILTER_SYSCALLS reg_tmp1 reg_tmp2
    lui  \reg_tmp1, %tprel_hi(pk_trusted_tls)
    add  \reg_tmp1, \reg_tmp1, tp, %tprel_add(pk_trusted_tls)
    addi \reg_tmp1, \reg_tmp1, %tprel_lo(pk_trusted_tls)
    li   \reg_tmp2, TTLS_OFFSET_FILTER_SYSCALLS
    add  \reg_tmp1, \reg_tmp1, \reg_tmp2 //add offset to address

    /* cannot do these checks anymore
    #ifndef RELEASE
    //assert before set:
    ld   \reg_tmp2, 0(\reg_tmp1)
    //beq  \reg_tmp2, zero, fail
    ASSERT_WITH_INFO2 __LINE__ bne  \reg_tmp2 zero
    #endif
    */

    //unset value
    sd   zero, 0(\reg_tmp1)
.endm

# ------------------------------------------------------------------------------

.macro CALL_C_HANDLER
    //csrrw zero, CSR_UEPC, ra
    call _pk_exception_handler_arch_c # returns the type in a0
.endm
# ------------------------------------------------------------------------------
.section .text

//.section .pk_utvec_table,"ax",@progbits
.section .pk_utvec_table,"a",@progbits
//.section .pk,"a",@progbits
.global pk_utvec_table
//.align 4 # must be aligned on a 4-byte boundary according to RISC-V priv spec
// But since pk_utvec_table goes straight into utvec, its lowest 6 bits might be 
// ORed with the exception/interrupt cause*4 (4, because instructions are that 
// size, and so are entries in the vector table).
// Since there are at least 16 causes, cause takes up 4 bits.
// Thus, cause * 4 takes up 6 bits. This means that the lowest 6 bits of 
// the address of pk_utvec_table need to be 0.
// Ariane and Ibex have a 256-byte alignment requirement, thus we use .align 8
.align 8
pk_utvec_table:
    j fail                   //  0
    j fail                   //  1
    j fail                   //  2
    j fail                   //  3
    j fail                   //  4
    j fail                   //  5
    j fail                   //  6
    j fail                   //  7
    j _pk_syscall_handler    //  8
    j fail                   //  9
    j fail                   // 10
    j fail                   // 11
    j fail                   // 12
    j fail                   // 13
    j _pk_exception_handler  // 14
    j fail                   // 15
.section .text

# ------------------------------------------------------------------------------

.section .pk,"a",@progbits
.global fail
fail:
    ASSERT_WITH_INFO0 __LINE__ j
    DIE
.section .text

# ------------------------------------------------------------------------------

.section .pk,"a",@progbits
.global _pk_exception_syscall
.align 4
_pk_exception_syscall:
.skip  4

.global _pk_exception_handler
.align 4
_pk_exception_handler:
    // load secure exception handler stack from uscratch:
    // we have to do this before saving any registers because otherwise we'd
    // write to an arbitrary memory location with higher priviledges
    // since the pkeys aren't checked in the exception handler mode
    csrrw sp, CSR_USCRATCH, sp

    //allocate frame and save the essential registers
    ALLOCATE_FRAME(0xC00C1E)
    SAVE(ra)

    /*
    if utval != _pk_exception_handler
        set type to something invalid
    */
    //Save registers which we're using for calculations.
    //Especially important for non-deliberate calls (=exceptions)
    SAVE(t5)
    SAVE(t6)
    SAVE(reg_a2_type)

    //unset filter_syscalls bit (for ptrace/seccomp_user)
    UNSET_FILTER_SYSCALLS t5 t6

    //enable full protection key access in kernel
    li t6, FULL_ACCESS_BIT
    csrrs zero, CSR_MPK, t6

    csrr t6, CSR_UTVAL
    la   t5, _pk_exception_handler
    sub  t6, t6, t5
    beqz t6, _pk_deliberate_call
    //not a deliberate call: set type
    li reg_a2_type, 0xFFFFFFFF //set type to something invalid (for the dispatching/comparison below)
    j _pk_normal // skip setting uepc, because it was a normal missing-key-exception and not a deliberate call
_pk_deliberate_call:
    csrrw zero, CSR_UEPC, ra
_pk_normal:
    //Restore registers used for earlier calculations.
    //NOTE: reg_a2_type is restored later in _pk_other_end
    //(because we still need its now-different value within the C handler)
    RESTORE(t6)
    RESTORE(t5)

    // once we know if it's a a real exception (which means that reg_* are wrong)
    // we can do things more efficiently without saving all the regs

    //dispatch based on reg_a2_type
    // 0 = eret, 1 = ecall, 2 = api
    beqz reg_a2_type, _pk_handle_eret
    addi reg_a2_type, reg_a2_type, -1
    beqz reg_a2_type, _pk_handle_ecall
    addi reg_a2_type, reg_a2_type, -1
    beqz reg_a2_type, _pk_handle_api
    addi reg_a2_type, reg_a2_type, -1
    beqz reg_a2_type, _pk_handle_syscall_ret
    j _pk_handle_other

_pk_handle_eret:
    RESTORE(reg_a2_type)
    //save necessary registers: return values
    //which are in t0..t2 because of GEN_CALLEE_WRAPPER
    SAVE(t0)
    SAVE(t1)
    //SAVE(t2)
    //
    CALL_C_HANDLER
    //
    j _pk_eret_end
_pk_handle_syscall_ret:
    //SAVE(ra)
    call sf_monitor_syscall_exit_handler
    RESTORE(ra)

    //RESTORE(t6)
    //RESTORE(t5)

    DELETE_FRAME(0xC00C1E)
    RESTORE_FRAME_SYS_HANDLER
    j _pk_exception_handler_end
_pk_handle_ecall:
    RESTORE(reg_a2_type)

    //Save all arguments to the ecall function
    //because they will be overwritten by our C handler before we get to the call
    //Note a0..a2 arguments are actually in t0..t2
    SAVE(t0)
    SAVE(t1)
    SAVE(t2)

    SAVE(a3)
    SAVE(a4)
    SAVE(a5)
    SAVE(a6)
    SAVE(a7)

    //Note: No need to save callee-saved regs since they're handled by GEN_CALL_WRAPPER
    CALL_C_HANDLER
    j _pk_ecall_end
_pk_handle_api:
    //RESTORE(reg_a2_type) // we don't need the type anymore
    //Note we could also use reg_a2_type instead of t5, but t5 is caller-saved anyway
    //
    //check if API id is valid (if id < api table size)
    li  t5, API_TABLE_SIZE
    //bge reg_a1_id, t5, fail // or _pk_handle_other for semi-graceful error handling?
    ASSERT_WITH_INFO2 __LINE__ bge reg_a1_id t5
    //look up API address in api table and store address in t5
    slli reg_a1_id, reg_a1_id, 3 // multiply id with wordsize so that we can use the result as an offset to the api table
    la   t5, _pk_api_table             // t5 = address of api table
    add  t5, t5, reg_a1_id          // t5 = address of _pk_api_table[reg_a1_id]
    ld t5, 0(t5)                       // t5 = address of API function
    //
    // restore api-function arguments from tmp-regs
    // Note: they were stored in tmp-regs in GEN_CALL_WRAPPER_API
    TMP_REGS_TO_ECALL
    //call API function
    jalr ra, t5, 0 // store return address in ra and jump to API function

    // at this point a0,a1 should contain the return value
    j clear_stack_and_end
_pk_handle_other:
    li reg_a2_type, TYPE_EXCEPTION //NOTE: we could remove this if we swap out 0xFFFFFF above with TYPE_EXCEPTION
    //save all registers
    SAVE(t0)
    SAVE(t1)
    SAVE(t2)
    SAVE(s0)
    SAVE(a0)
    SAVE(a1)
    //NOTE: a2 (=reg_a2_type) is not being saved, because we did so earlier and by now it contains a different value.
    SAVE(a3)
    SAVE(a4)
    SAVE(a5)
    SAVE(a6)
    SAVE(a7)
    SAVE(t3)
    SAVE(t4)
    SAVE(t5)
    SAVE(t6)
    //
    CALL_C_HANDLER
    beqz a0, _pk_other_end // If _pk_exception_handler_arch_c returned non-zero, we want to call user_exception_handler(badaddr)
    csrr a0, utval         // Load badaddr into a0
    SAVE(a0)
    j _pk_other_end

_pk_eret_end:
    //
    // Returning from ECALL
    // discard all registers except return values
    RESTORE(t0)
    RESTORE(t1)
    //RESTORE(t2)
    // clear one stack frame from the exception handler, because this was the frame from the RET
    // but now we need to restore RA from the previous frame (where we had a CALL)
    DELETE_FRAME(0xC00C1E)
    // callee-saved regs are handled by GEN_CALL_WRAPPER, caller-saved by the caller
    // no other registers (apart form RA) have to be restored
    RESTORE(ra)
    //
    j clear_stack_and_end


_pk_ecall_end:
    // just restore the arguments (or just all the a* regs)
    // also some t-regs because they may contain arguments
    // Note: we restore the arguments, because they were probably overwritten in
    // the C handler. but they're needed now that we actually call the ECALL function

    //Note a0..a2 arguments are actually in t0..t2
    RESTORE(t0)
    RESTORE(t1)
    RESTORE(t2)

    RESTORE(a3)
    RESTORE(a4)
    RESTORE(a5)
    RESTORE(a6)
    RESTORE(a7)
    // NOTE: we jump straight to the end, without deleting the stack frame,
    //       because we need it later when we return from the ecall!
    j _pk_exception_handler_end

_pk_other_end:
    // return from normal (missing-key-)exception and restore all the registers
    RESTORE(ra)
    RESTORE(t0)
    RESTORE(t1)
    RESTORE(t2)
    RESTORE(s0)
    RESTORE(a0)
    RESTORE(a1)
    RESTORE(a2)
    RESTORE(a3)
    RESTORE(a4)
    RESTORE(a5)
    RESTORE(a6)
    RESTORE(a7)
    RESTORE(t3)
    RESTORE(t4)
    RESTORE(t5)
    RESTORE(t6)

clear_stack_and_end:
    DELETE_FRAME(0xC00C1E)

.global _pk_exception_handler_end
_pk_exception_handler_end:
    sd t6, -8(sp) //we have no stack frame here, so we use negative offsets

    //disable full pkey access in kernel
    li t6, FULL_ACCESS_BIT
    csrrc zero, CSR_MPK, t6

    //unset filter_syscalls bit (for ptrace/seccomp_user)
    sd t5, -16(sp)
    SET_FILTER_SYSCALLS t6 t5
    ld t5, -16(sp)

    ld t6, -8(sp)

    csrrw sp, CSR_USCRATCH, sp
    uret
# ------------------------------------------------------------------------------

.global _pk_syscall_handler
_pk_syscall_handler:
    csrrw sp, CSR_USCRATCH, sp
    SAVE_FRAME_SYS_HANDLER

    //unset filter_syscalls bit (for ptrace?)
    UNSET_FILTER_SYSCALLS t1 t0 //t0,t1 is saved by SAVE_FRAME_SYS_HANDLER

    // s1 is preserved over call to 'sf_monitor_syscall_handler_riscv'
    csrr s1, CSR_UEPC      // Resume at instruction following ecall (UEPC+4)
    addi s1, s1, 4
    csrw CSR_UEPC, s1

    //enable full pkey access in kernel
    li t5, FULL_ACCESS_BIT
    csrrs zero, CSR_MPK, t5
    RESTORE(t5)

    call sf_monitor_syscall_handler_riscv

    //disable full pkey access in kernel
    li t5, FULL_ACCESS_BIT
    csrrc zero, CSR_MPK, t5
    RESTORE(t5)

    // check, if UEPC was changed in handler
    // if so, do not delete stack frame
    csrr t5, CSR_UEPC
    bne t5, s1, _handle_syscall_end
    RESTORE_FRAME_SYS_HANDLER

_handle_syscall_end:

    //set filter_syscalls bit (for ptrace?)
    SLOW_PUSH t0
    SLOW_PUSH t1
    SET_FILTER_SYSCALLS t0 t1
    SLOW_POP t1
    SLOW_POP t0

    csrrw sp, CSR_USCRATCH, sp
    uret

# ------------------------------------------------------------------------------
_pk_assert:
    # Prepare an assert frame with all registers on the _pk_assert_stack
    // Note: ASSERT_WITH_INFO pushes to PIC(_pk_assert_stack_top-8)
    //csrrw sp, CSR_USCRATCH, sp //"save" sp in uscratch
    //toto save sp + uscratch

    la sp, _pk_assert_stack_top
    // note: _pk_assert_stack_top-8 holds "info".
    addi sp, sp, -16
    SLOW_PUSH ra
    SLOW_PUSH t0
    SLOW_PUSH t1
    SLOW_PUSH t2

    SLOW_PUSH s0
    SLOW_PUSH s1

    SLOW_PUSH a0
    SLOW_PUSH a1
    SLOW_PUSH a2
    SLOW_PUSH a3
    SLOW_PUSH a4
    SLOW_PUSH a5
    SLOW_PUSH a6
    SLOW_PUSH a7

    SLOW_PUSH s2
    SLOW_PUSH s3
    SLOW_PUSH s4
    SLOW_PUSH s5
    SLOW_PUSH s6
    SLOW_PUSH s7
    SLOW_PUSH s8
    SLOW_PUSH s9
    SLOW_PUSH s10
    SLOW_PUSH s11

    SLOW_PUSH t3
    SLOW_PUSH t4
    SLOW_PUSH t5
    SLOW_PUSH t6

    mv a0, sp // first argument of c function
    j _pk_assert_c
    DIE
# ------------------------------------------------------------------------------
.bss
.align WORDSIZE
# bottom of stack
.type _pk_assert_stack, @object
.size _pk_assert_stack, 1024*WORDSIZE
_pk_assert_stack:
.skip 1024*WORDSIZE
# end of stack (exclusive)
.type _pk_assert_stack_top, @object
.size _pk_assert_stack_top, 8
_pk_assert_stack_top:
.section .text
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
.section .text
# ------------------------------------------------------------------------------
// WARNING CODE BELOW is not protected! (outside of the pk section)

// called by syscall filter to return to monitor
.global _sf_domain_syscall_handler
_sf_domain_syscall_handler:
    call sf_domain_syscall_handler
    goto_exception_handler_preserve_ra 0 TYPE_SYSCALL_RET
    //unreachable code
    ASSERT_WITH_INFO0 __LINE__ j

