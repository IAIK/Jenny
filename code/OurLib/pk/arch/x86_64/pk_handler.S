#define __ASSEMBLY__
#include "pk_internal.h"

#ifndef RELEASE
.macro ASSERT_WITH_INFO jump_instruction info
    \jump_instruction 1f
    jmp 2f
    1:
    movq \info, PIC(_pk_assert_stack_top-8)
    jmp _pk_assert
    2:
.endm
#else
.macro ASSERT_WITH_INFO jump_instruction info
    \jump_instruction _pk_assert
.endm
#endif

########################################################################

.macro ASSERT_NO_DOUBLE_ENTER
#ifndef RELEASE
    push %rax
    push %rcx
    push %rdx
    xor %ecx, %ecx  # must be 0 for wrpkru
    xor %edx, %edx  # must be 0 for wrpkru

    # Check that we did not accidentially enter monitor twice, 
    # e.g., performed an API call inside an API call
    rdpkru
    test %eax, %eax
    # ATTENTION: ASSERT_WITH_INFO uses local jump targets 1: and 2:
    # which we should not use elsewhere in this macro
    ASSERT_WITH_INFO jz $__LINE__

    pop %rdx
    pop %rcx
    pop %rax
#endif
.endm

.macro LOAD_PKRU_GADGET label
    # This is a safe wrpkru gadget loading pkru from CURRENT_PKRU
    # We re-fetch CURRENT_PKRU from protected read-only TLS after wrpkru
    # to ensure noone jumped to wrpkru illegitimately

    LOAD_ROTTLS_ADDRESS(CURRENT_PKRU, %rax)
    mov %fs:(%rax), %rax
    xor %ecx, %ecx        # must be 0 for wrpkru
    xor %edx, %edx        # must be 0 for wrpkru
    wrpkru
    LOAD_ROTTLS_ADDRESS(CURRENT_PKRU, %rcx)
    mov %fs:(%rcx), %rcx
    cmp %rax, %rcx
    je \label
    ud2                   # someone jumped to wrpkru illegitimately, die now
.endm

.macro ENTER_EXCEPTION
    # clear status flags (see A Tale of Two Worlds)
    cld # clear direction flag (for string operations)

#ifndef FAKE_MPK_REGISTER
    # We're currently still on the unprotected user stack
    # we need to save/restore rax,rcx,rdx because they're 
    # return values and arguments for ecalls/ocalls
    push %rax
    push %rcx
    push %rdx
    xor %ecx, %ecx  # must be 0 for wrpkru
    xor %edx, %edx  # must be 0 for wrpkru
    xor %eax, %eax  # eax holds pkru value, which is also 0 to give
    wrpkru          # full permissions to exception handler
                    # Now, trusted TLS can be accessed
    test %eax, %eax
    jz 1f
    ud2             # someone jumped to wrpkru illegitimately, die now
1:
    pop %rdx
    pop %rcx
    pop %rax
#endif

    LOAD_TTLS_ADDRESS(FILTER_SYSCALLS, %r10)
    movq $0, %fs:(%r10)

    # store user stack
    mov %rsp, %r11       # keep a copy of user stack in %r11
    LOAD_TTLS_ADDRESS(BACKUP_USER_STACK, %r10)
    mov %rsp, %fs:(%r10)

    # load exception stack
    LOAD_TTLS_ADDRESS(EXCEPTION_STACK, %r10)
    mov %fs:(%r10), %rsp

    # initialize argframe.valid=0
    LOAD_TTLS_ADDRESS(ARGFRAME, %r10)
    movq $0, %fs:(%r10)

    # disable syscall handling (handler is at constant offset to fs)
    # movq $0, %fs:(INDIRECT_CALL_OFFSET)
.endm

########################################################################

.macro CLEANUP_EXCEPTION_WITH_PUSHED_RAX_RDX

    LOAD_TTLS_ADDRESS(SIGNAL_PENDING, %rax)
    mov %fs:(%rax), %eax
    test %eax, %eax
    jz 2f # zero
    cmp $(SIGNAL_DEFERRED), %eax
    je 2f

    ##################
    # SIGNAL_PENDING #
    ##################

    # We have a pending signal that we need to redeploy
    # As long as we are on the monitor stack
    # - redeploy signal with tgkill
    # - clear signal_pending flag
    # - copy sigaction to user stack ????

    # Save all caller-saved registers on user stack
    # Note: push original %rax and %rdx from exception stack
    # restore user stack, and keep exception stack in %rdx
    mov  %rsp, %rdx
    LOAD_TTLS_ADDRESS(BACKUP_USER_STACK, %rax)
    mov %fs:(%rax), %rsp
    push 8(%rdx)          # original %rax
    push %rcx
    push 0(%rdx)          # original %rdx
    push %rsi
    push %rdi
    push %r8
    push %r9
    push %r10
    push %r11
    push %rbp

    # switch back to exception stack
    mov %rsp, %rbp
    mov %rdx, %rsp

    # Redeploy signal and
    # Prepare arguments for sigprocmask in ARGFRAME
    call PCREL(_pk_signal_prepare_sigprocmask)

    # Store a backup of our current pkru value
    # since it will be destroyed during signal redeployment
    LOAD_ROTTLS_ADDRESS(CURRENT_PKRU, %r10)
    mov %fs:(%r10), %r10
    LOAD_ROTTLS_ADDRESS(BACKUP_PKRU, %r11)
    mov %r10, %fs:(%r11)

    # restore user stack
    mov %rbp, %rsp
    pop %rbp

    # Do sigprocmask syscall, which will be immediately
    # interrupted by the redeployed signal. Thus, 
    # DO NOT USE MONITOR STACK AFTER HERE
    LOAD_TTLS_ADDRESS(ARGFRAME, %r10)
    add $0x8, %r10 # skip type field
    mov %fs:(%r10), %rax
    add $0x8, %r10
    mov %fs:(%r10), %rdi
    add $0x8, %r10
    mov %fs:(%r10), %rsi
    add $0x8, %r10
    mov %fs:(%r10), %rdx
    add $0x8, %r10
    mov %fs:(%r10), %r10
    syscall

    # The unblocked redeployed signal will traverse, as follows:
    # 1) _pk_sigaction_trampoline with signal_pending = SIGNAL_DEFERRED
    # 2) __pk_signal_handler --> pk_signal_handler_c
    # 3) _pk_signal_handler_domain
    # 4) the domain's registered handler
    # 5) _pk_signal_handler_domain_ret
    # 6) _pk_signal_handler_exit_c, setting signal_pending = 0 and signal_state = SIGNAL_RESUME
    # 7) _prepare_pkru_swap_c, setting asm_pkru=0 and signal_state to SIGNAL_NONE
    # 8) resume at the return point of 1), doing an rt_sigreturn
    # 9) we will arrive back here with pkru=0

    # restore original pkru value that has been destroyed by step 7)
    LOAD_ROTTLS_ADDRESS(BACKUP_PKRU, %r11)
    mov %fs:(%r11), %r11
    LOAD_ROTTLS_ADDRESS(CURRENT_PKRU, %r10)
    mov %r11, %fs:(%r10)

    # enable syscall handling again (handler is at constant offset to fs)
    mov PIC(_pk_syscall_handler_ptr), %rdx
    movq %rdx, %fs:(INDIRECT_CALL_OFFSET)

    # set filter_syscalls
    LOAD_TTLS_ADDRESS(FILTER_SYSCALLS, %rax)
    movq $1, %fs:(%rax)

#ifndef FAKE_MPK_REGISTER 
    LOAD_PKRU_GADGET 1f
1:
    ####################################################################
    # now we don't have access to exception stack anymore
    ####################################################################
#endif

    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rax
    jmp 4f

2:
    ##################################
    # SIGNAL_NONE or SIGNAL_DEFERRED #
    ##################################
    # enable syscall handling again (handler is at constant offset to fs)
    mov PIC(_pk_syscall_handler_ptr), %rdx
    movq %rdx, %fs:(INDIRECT_CALL_OFFSET)

    mov  %rsp, %rdx                  # keep our exception stack

    # restore user stack
    LOAD_TTLS_ADDRESS(BACKUP_USER_STACK, %rax)
    mov %fs:(%rax), %rsp

    # set filter_syscalls
    LOAD_TTLS_ADDRESS(FILTER_SYSCALLS, %rax)
    movq $1, %fs:(%rax)

    ####################################################################
    # We are back on the user stack
    # The exception stack is still accessible under %rdx
    ####################################################################


    # Before doing the PKRU switch, push original %rax and %rdx
    # from exception stack to user stack
    # Since we still have access to user stack after updating PKRU, 
    # we can restore them afterwards

    push 8(%rdx)          # original %rax
    push 0(%rdx)          # original %rdx

#ifndef FAKE_MPK_REGISTER 
    push %rcx

    LOAD_PKRU_GADGET 3f
3:

    ####################################################################
    # now we don't have access to exception stack anymore
    ####################################################################

    pop %rcx
#endif
    pop %rdx
    pop %rax
4:
.endm

########################################################################

.macro PREPARE_RETARGS_WITH_PUSHED_RAX_RDX
    # check if we need to restore user arguments/return values
    LOAD_TTLS_ADDRESS(ARGFRAME, %rax)
    mov %fs:(%rax), %rdx

    cmp $(TYPE_CALL), %rdx
    jne 1f
    # restore function call arguments
    add $0x8, %rax
    mov %fs:(%rax), %rdi
    add $0x8, %rax
    mov %fs:(%rax), %rsi
    add $0x8, %rax
    mov %fs:(%rax), %rdx
    mov %rdx, 0(%rsp)
    add $0x8, %rax
    mov %fs:(%rax), %rcx
    add $0x8, %rax
    mov %fs:(%rax), %r8
    add $0x8, %rax
    mov %fs:(%rax), %r9
1:
.endm

########################################################################

.section .pk,"a",@progbits

.global pk_exception_handler              # Externally visible
.type   pk_exception_handler, @function
pk_exception_handler:

.type   _pk_exception_handler, @function
_pk_exception_handler:                    # For internal rip-relative addressing

    ASSERT_NO_DOUBLE_ENTER
    ENTER_EXCEPTION

    ####################################################################
    # From now on, we operate on the exception stack
    # Since our exception stack is always 16-byte aligned (psabi),
    # we need to push/pop an even number of times before doing C-calls
    #
    # The original user stack is available under %r11
    ####################################################################

    # Test type
    cmp $(TYPE_CALL), rdi_type
    je _pk_handle_ecall
    cmp $(TYPE_RET),  rdi_type
    je _pk_handle_eret
    cmp $(TYPE_API),  rdi_type
    je _pk_handle_apicall
    cmp $(TYPE_SYSCALL_RET),  rdi_type
    je _pk_handle_syscall_ret
    cmp $(TYPE_SIGNAL_RET), rdi_type
    je _pk_handle_signal_ret
    ASSERT_WITH_INFO jmp $__LINE__

    #####################################
    # dispatch API calls
    #####################################
_pk_handle_apicall:

    cmp $(API_TABLE_SIZE), rsi_id
    ASSERT_WITH_INFO jge $__LINE__

    # Load correct API function pointer into %r10
    shl $3, rsi_id                # Multiply id with WORDSIZE
    lea PIC(_pk_api_table), %r10  # Load API table
    add rsi_id, %r10              # Find correct entry

    # Restore original API arguments from user stack
    mov 16(%r11), %rdi # restore arg1
    mov  8(%r11), %rsi # restore arg2
                       # arg3 ... arg6 are unmodified

    # Do actual API call
    call *(%r10)

    # Preserve return value of API call
    push %rax
    push %rdx
    call PCREL(_prepare_pkru_swap_c)

    jmp _pk_exception_handler_end_with_pushed_rax_rdx

    #####################################
    # Dispatch ECALL
    #####################################
_pk_handle_ecall:

    # Store caller-saved registers for c-function call
                       # arg1 is on user stack
                       # arg2 is on user stack
    push %rcx          # store arg3
    push %rdx          # store arg4
    push %r8           # store arg5
    push %r9           # store arg6
    push %r11          # store user stack of caller
    add $-0x8, %rsp    # to avoid psabi misalignment

    call PCREL(_pk_exception_handler_arch_c)
    call PCREL(_prepare_pkru_swap_c)

    add $0x8, %rsp     # to avoid psabi misalignment
    pop %r11           # restore user stack pointer of caller
    pop %r9            # restore arg6
    pop %r8            # restore arg5
    pop %rdx           # restore arg4
    pop %rcx           # restore arg3
    mov  8(%r11), %rsi # restore arg2
    mov 16(%r11), %rdi # restore arg1

    jmp _pk_exception_handler_end

    #####################################
    # Dispatch ERET (return from ECALL)
    #####################################
_pk_handle_eret:

    # Store caller-saved return registers for c-function call
    push %rax          # store return register 1
    push %rdx          # store return register 2
    call PCREL(_pk_exception_handler_arch_c)
    call PCREL(_prepare_pkru_swap_c)

    jmp _pk_exception_handler_end_with_pushed_rax_rdx

_pk_handle_syscall_ret:
    call PCREL(sf_monitor_syscall_exit_handler)
    push %rax
    push %rdx
    jmp _pk_syscall_handler_end_with_pushed_rax_rdx

_pk_handle_signal_ret:
    call PCREL(_pk_signal_handler_exit_c)
    call PCREL(_prepare_pkru_swap_c)
    # fall-through to _pk_exception_handler_end
    
#-----------------------------------------------------------------------
.global _pk_exception_handler_end
_pk_exception_handler_end:
    push %rax
    push %rdx
_pk_exception_handler_end_with_pushed_rax_rdx:
    PREPARE_RETARGS_WITH_PUSHED_RAX_RDX
    CLEANUP_EXCEPTION_WITH_PUSHED_RAX_RDX
    return_from_exception

########################################################################

#ifndef FAKE_MPK_REGISTER 

// Execute syscall with specific protection keys
.global _pk_syscall_asm
_pk_syscall_asm: # (a0, a1, a2, a3, a4, a5, sysnopk)
    # push all callee-saved registers
    push %r12
    mov 16(%rsp), %r12
    push %r13
    push %r14
    push %r15
    push %rbx
    push %rbp

    # 64-ABI      syscall-ABI
    # a0 rdi         rdi
    # a1 rsi         rsi
    # a2 rdx         rdx
    # a3 rcx  -->    r10
    # a4 r8          r8
    # a5 r9          r9
    # sysno 8(rsp)   rax

    mov %rcx, %r10    # move a3 to correct reg
    mov %rdx, %r11    # save rdx

    # store exception stack in BACKUP_EXCEPTION_STACK
    LOAD_TTLS_ADDRESS(BACKUP_EXCEPTION_STACK, %r13)
    mov %rsp, %fs:(%r13)

    LOAD_PKRU_GADGET 1f
1:
    # exception stack is now inaccessible

    mov %r11, %rdx     # restore rdx
    mov %r12, %rax      # restore sysno

    syscall

    # Kernel destroys rcx and r11
    mov %rax, %r11        # save return value

    # Safe wrpkru gadget that acts like a reentrant-safe monitor entry point.
    # Since a ROP attacker could jump here illegitimately, we check
    # whether a syscall is currently being impersonated by checking and
    # restoring BACKUP_EXCEPTION_STACK from monitor memory.
    # Furthermore, we restore all callee-saved registers.
    xor %eax, %eax        # Allow full access again
    xor %ecx, %ecx        # must be 0 for wrpkru
    xor %edx, %edx        # must be 0 for wrpkru
    wrpkru
    # exception stack is now accessible again

    mov %r11, %rax        # restore return value

    LOAD_TTLS_ADDRESS(BACKUP_EXCEPTION_STACK, %r12)
    movq %fs:(%r12), %rsp
    test %rsp, %rsp
    jnz 2f
    ud2       # Someone illegitimately jumped to this gadget
2:
    movq $0, %fs:(%r12)   # delete BACKUP_EXCEPTION_STACK to prevent
                          # anyone from re-entering here a second time
    # restore callee-saved registers
    pop %rbp
    pop %rbx
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    ret
#endif // FAKE_MPK_REGISTER 

_pk_assert:
    # Prepare an assert frame with all registers on the _pk_assert_stack
    // Note: ASSERT_WITH_INFO pushes to PIC(_pk_assert_stack_top-8)
    mov %rsp, PIC(_pk_assert_stack_top-16)   # Save rsp before switching stack
    lea PIC(_pk_assert_stack_top-16), %rsp   # Switch to _pk_assert_stack
    push %rbp
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15
#ifndef FAKE_MPK_REGISTER
    xor %ecx, %ecx
    xor %edx, %edx
    rdpkru
    push %rax

    # Give _pk_assert_c full pkru access
    xor %eax, %eax
    wrpkru
#else
    add $-8, %rsp // psabi alignment
#endif

    # disable syscall interception
    # mov PIC(_pk_syscall_handler_ptr), %rdx
    # movq $0, %fs:(INDIRECT_CALL_OFFSET)

    mov %rsp, %rdi
    jmp _pk_assert_c
    DIE

.global pk_do_init
.type   pk_do_init, @function
pk_do_init:
    # Call _pk_init
    add $-0x8, %rsp      # to avoid psabi misalignment
    call PCREL(_pk_init)
    add $0x8, %rsp       # to avoid psabi misalignment

    cmp $0xffffffff,%eax
    je pk_do_init_end

    push %rax            # store return value

    # Load asm_pkru config
    call PCREL(_prepare_pkru_swap_c)

#ifndef FAKE_MPK_REGISTER
    # We are in a weird situation now: 
    # * _pk_init operated on the thread stack rather than the exception stack
    # * _pk_init directly returned to us instead of the pk_exception_handler
    # So, we must take care to configure pkru properly ourselves
    # We still have full pkru access to all allocated keys
    # This is no problem, as an attacker that tampers with this code
    # could also have tampered with the protection handler before it is
    # properly initialized

    LOAD_PKRU_GADGET 1f
1:

    ####################################################################
    # now we don't have access to protection handler anymore
    ####################################################################
#endif
    pop %rax              # restore return value
pk_do_init_end:
    return_from_exception

########################################################################

.global _pk_syscall_handler              # Externally visible
.type   _pk_syscall_handler, @function
_pk_syscall_handler:
    # syscall arrives here with misaligned stack

    # Switch from syscall ABI to function call ABI
    push %rcx           # Push rcx (return address) on user stack, now we are 16-byte stack aligned
    mov %r10, %rcx      # restore arg3

    # push caller-saved registers on user stack since we
    # must preserve them irrespective of the caller
    push %rdi
    push %rsi
    push %rdx
    # leave out rcx
    push %r8
    push %r9
    push %r10

    ASSERT_NO_DOUBLE_ENTER
    ENTER_EXCEPTION

    add $-8, %rsp         # Push 'dofilter' as eighth argument
    mov %rsp, (%rsp)      # which is a pointer to itself
    push %rax             # Push sysno as seventh argument
    call PCREL(sf_monitor_syscall_handler_x86_64)

    # Check if eighth argument 'dofilter' has been set to one
    mov 0x8(%rsp), %r11 # Load last pointer value
    sub $1, %r11
    jz _pk_syscall_delegate
    
    # The syscall was executed by sf_monitor_syscall_handler_x86_64
    # %rax contains the syscall return value
    # We continue with the original caller of the syscall

    mov %rax, 0x8(%rsp)          # store syscall return value on stack
    call PCREL(_prepare_pkru_swap_c)

    # We've already pushed two elements
    # 1. for rax, the syscall return value
    # 2. for rdx, an unused value (our original syscall number)
    #    It will be restored anyways
_pk_syscall_handler_end_with_pushed_rax_rdx:
    CLEANUP_EXCEPTION_WITH_PUSHED_RAX_RDX

    # Restore caller-saved registers
    pop %r10
    pop %r9
    pop %r8
    # leave out rcx
    pop %rdx
    pop %rsi
    pop %rdi

    return_from_exception

#############
_pk_syscall_delegate:
    # The syscall is delegated by sf_monitor_syscall_handler_x86_64
    # %rax contains the first argument of the filter function
    # Provide it in %rdi

    # We've already two elements pushed which we do not need anymore
    # and are normally used to pass a return value in rax/rdx

    mov %rax, 0x8(%rsp) # temporarily store argument on stack
    call PCREL(_prepare_pkru_swap_c)
    mov 0x8(%rsp), %rdi # restore argument for filter function

    jmp _pk_exception_handler_end_with_pushed_rax_rdx

########################################################################

.global _pk_signal_handler              # Externally visible
.type   _pk_signal_handler, @function
_pk_signal_handler:
    ENTER_EXCEPTION
    call PCREL(_pk_signal_handler_c)
    call PCREL(_prepare_pkru_swap_c)
    jmp _pk_exception_handler_end

########################################################################
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

########################################################################
.section .text
########################################################################
.global _sf_domain_syscall_handler
.type   _sf_domain_syscall_handler, @function
_sf_domain_syscall_handler:
    add $-0x8, %rsp      // to avoid psabi misalignment

    call PCREL(sf_domain_syscall_handler)
    mov $(TYPE_SYSCALL_RET),   rdi_type

    add $0x8, %rsp      // to avoid psabi misalignment
    trigger_exception

    ASSERT_WITH_INFO jmp $__LINE__

########################################################################
.global _pk_signal_handler_domain
.type   _pk_signal_handler_domain, @function
_pk_signal_handler_domain:
    push %rcx // domain handler is stored in 4th argument. Call it
    call *(%rsp)
    mov $(TYPE_SIGNAL_RET),   rdi_type
    add $0x8, %rsp
    trigger_exception

    ASSERT_WITH_INFO jmp $__LINE__

########################################################################
.global _pk_signal_handler_domain_ret
.type   _pk_signal_handler_domain_ret, @function
_pk_signal_handler_domain_ret:
    # Currently unused

