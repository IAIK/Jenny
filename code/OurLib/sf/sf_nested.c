#include "sf_internal.h"
#include "pk.h"
#include "pk_internal.h"
#include "sysfilter.h"
#include "test2_ecall.h"
#include <assert.h>
#include <sys/syscall.h>

__thread int _sf_impersonate = -1;

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
#ifdef __x86_64__

# define REGISTERS_CLOBBERED_BY_SYSCALL "cc", "r11", "cx"

static inline long _sf_syscall_direct(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5)
{
    long resultvar;
    register long _a5 asm ("r9")  = arg5;
    register long _a4 asm ("r8")  = arg4;
    register long _a3 asm ("r10") = arg3;
    register long _a2 asm ("rdx") = arg2;
    register long _a1 asm ("rsi") = arg1;
    register long _a0 asm ("rdi") = arg0;
    asm volatile (
    "syscall\n\t"
    : "=a" (resultvar)
    : "0" (nr), "r" (_a0), "r" (_a1), "r" (_a2), "r" (_a3), "r" (_a4),
      "r" (_a5)
    : "memory", REGISTERS_CLOBBERED_BY_SYSCALL);
    return resultvar;
}
//------------------------------------------------------------------------------

extern long _pk_syscall_asm(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long sysno_pkru);

long _sf_syscall_pkru(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, pkru_config_t pkru)
{
    long return_value = -1;
    //assert_ifdebug(PKRU_TO_INT(pkru) & SYSFILTER_DELEGATE_MASK);
    pkru &= ~SYSFILTER_DELEGATE_MASK; // clear bit to notify sysfilter module not to delegate this syscall
    //assert_ifdebug(!(PKRU_TO_INT(pkru) & SYSFILTER_DELEGATE_MASK));
    assert(0 == pthread_mutex_unlock(&pk_data.mutex)); // We need to release mutex in case our syscall blocks the thread (e.g. pthread_join)
    PREPEND_TO_DEBUG_BUFFER("Setting PKRU to 0x%lx\n", PKRU_TO_INT(pkru));

#ifdef FAKE_MPK_REGISTER
    return_value = _sf_syscall_direct(nr, arg0, arg1, arg2, arg3, arg4, arg5);
#else // FAKE_MPK_REGISTER
    // Execute syscall with specific protection keys (pkey)
    // This needs to be done in assembler to avoid stack operations
    pk_trusted_tls.asm_pkru = pkru;
    return_value = _pk_syscall_asm(arg0, arg1, arg2, arg3, arg4, arg5, nr);
#endif  // FAKE_MPK_REGISTER
    assert(0 == pthread_mutex_lock(&pk_data.mutex));
    return return_value;
}
//------------------------------------------------------------------------------

long _sf_syscall(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5)
{
    return _sf_syscall_pkru(nr, arg0, arg1, arg2, arg3, arg4, arg5, read_pkru_current_thread(CURRENT_DID));
}
//------------------------------------------------------------------------------

#else // __x86_64__

// RISC-V

//copied from ../../testroot/glibc/sysdeps/unix/sysv/linux/riscv/sysdep.h
static inline long _sf_syscall_direct(long number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5)
{
    long int _sys_result;
    register long int __a7 asm ("a7") = number;
    register long int __a0 asm ("a0") = arg0;
    register long int __a1 asm ("a1") = arg1;
    register long int __a2 asm ("a2") = arg2;
    register long int __a3 asm ("a3") = arg3;
    register long int __a4 asm ("a4") = arg4;
    register long int __a5 asm ("a5") = arg5;
    __asm__ volatile (
    "scall\n"
    : "+r" (__a0)
    : "r" (__a7), "r" (__a1), "r" (__a2), "r" (__a3),
      "r" (__a4), "r" (__a5)
    : "memory");
    _sys_result = __a0;
    return _sys_result;
}
//------------------------------------------------------------------------------

__attribute__((always_inline)) static inline long _sf_syscall(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5)
{
    //disable full pkey access in kernel
    register uint64_t temp = FULL_ACCESS_BIT;
    asm volatile("csrrc zero, %[_csr_mpk], %[_temp];" :: [_csr_mpk] "i"(CSR_MPK), [_temp]"r"(temp));

    //syscall() is the libc wrapper that also sets errno.
    //internal_syscall6 only executes the syscall
    //int ret = syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
    long ret = _sf_syscall_direct(nr, arg0, arg1, arg2, arg3, arg4, arg5);

    //enable full pkey access in kernel
    asm volatile("csrrs zero, %[_csr_mpk], %[_temp];" :: [_csr_mpk] "i"(CSR_MPK), [_temp]"r"(temp));
    return ret;
}
//------------------------------------------------------------------------------

__attribute__((always_inline)) static inline long _sf_syscall_pkru(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, pkru_config_t pkru)
{
    int current_did = CURRENT_DID;
    //only load new pkru keys, but preserve did,mode,full_access!
    pkru_config_t old_config = read_pkru_current_thread(current_did);
    int old_previous_slot = pk_trusted_tls.thread_dom_data[current_did].previous_slot;

    pkru.sw_did      = old_config.sw_did;
    pkru.mode        = old_config.mode;
    pkru.full_access = old_config.full_access;
    //#define LOWEST_44_BITS (((uint64_t)1<<44)-1)
    //#define HIGHEST_20_BITS ((uint64_t)-1 & ~LOWEST_44_BITS)
    //pkru = INT_TO_PKRU((PKRU_TO_INT(old_config) & HIGHEST_20_BITS) | (PKRU_TO_INT(pkru) & LOWEST_44_BITS));

    // Do syscall
    //write_pkru_current_thread(current_did, pkru);
    pk_trusted_tls.thread_dom_data[current_did].current_pkru = pkru;
    _write_pkru_reg(pkru);
    PREPEND_TO_DEBUG_BUFFER("Setting PKRU to 0x%lx\n", PKRU_TO_INT(pkru));
    long ret = _sf_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);

    // Restore old config
    PREPEND_TO_DEBUG_BUFFER("Restoring PKRU to 0x%lx\n", PKRU_TO_INT(old_config));
    //write_pkru_current_thread(current_did, old_config);
    pk_trusted_tls.thread_dom_data[current_did].current_pkru = old_config;
    _write_pkru_reg(old_config);
    pk_trusted_tls.thread_dom_data[current_did].previous_slot = old_previous_slot;

    return ret;
}
//------------------------------------------------------------------------------

#endif // __x86_64__

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

PK_CODE_INLINE long _sf_do_syscall_impersonate(int filteree_did, long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {
    if(DID_INVALID != _sf_impersonate){

        assert_ifdebug(_domain_exists(_sf_impersonate));
        PREPEND_TO_DEBUG_BUFFER(COLOR_YELLOW "Impersonating syscall for %s\n", _pk_domain_str(_sf_impersonate));

        pkru_config_t old_config = read_pkru_current_thread(_sf_impersonate);
        int old_previous_slot = pk_trusted_tls.thread_dom_data[_sf_impersonate].previous_slot;

        // Load syscall_args_key
        pk_key_t * syscall_args_key = &pk_trusted_tls.syscall_args_key;
        if (!_pk_is_pkey_loaded_arch(syscall_args_key->pkey, old_config)) {
            if (unlikely(0 != _pk_domain_load_pkkey_unlocked(_sf_impersonate, syscall_args_key, PK_SLOT_ANY))) {
                ERROR_FAIL("unable to load syscall_args_key");
            }
        }

        // Perform actual syscall
        pkru_config_t config = read_pkru_current_thread(_sf_impersonate);
        assert_ifdebug( _pk_is_pkey_loaded_arch(syscall_args_key->pkey, config) );
        long ret = _sf_syscall_pkru(nr, arg0, arg1, arg2, arg3, arg4, arg5, config);

        // Unload syscall_args_key
        write_pkru_current_thread(_sf_impersonate, old_config);
        pk_trusted_tls.thread_dom_data[_sf_impersonate].previous_slot = old_previous_slot;

        return ret;
    } else {
        return _sf_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
    }
}
//------------------------------------------------------------------------------

PK_CODE_INLINE void _sf_set_ti_args(trace_info_t* ti, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {
    ti->args[0] = arg0;
    ti->args[1] = arg1;
    ti->args[2] = arg2;
    ti->args[3] = arg3;
    ti->args[4] = arg4;
    ti->args[5] = arg5;
}
//------------------------------------------------------------------------------

PK_CODE_INLINE void _print_flow(long nr)
{
    int filteree_did = CURRENT_DID;
    assert(nr >= 0 && nr < NUM_DOMAIN_FILTERS);
    sysent_t * monitor_filter = &sf_table[nr];

    const char * sys_name = sysno_to_str(nr);
    //PREPEND_TO_DEBUG_BUFFER(COLOR_CYAN "-------------------------------\n");
    PREPEND_TO_DEBUG_BUFFER(COLOR_CYAN " -- Domain %s invokes syscall %lu %s\n", _pk_domain_str(filteree_did), nr, sys_name);

    _pk_domain * _tmp_domain = &pk_data.domains[filteree_did];
    int          _tmp_domain_did = filteree_did;
    while(true){
        //check domain
        filter_compact_t * domain_filter = &_tmp_domain->sf_table[nr];
        if(domain_filter->filter == SYSCALL_DENIED){
            PREPEND_TO_DEBUG_BUFFER(COLOR_CYAN " -- Domain %s DENIES %s\n", _pk_domain_str(_tmp_domain_did), sys_name);
            break; //end loop
        }
        else if(domain_filter->filter == SYSCALL_ALLOWED){
            PREPEND_TO_DEBUG_BUFFER(COLOR_CYAN " -- Domain %s ALLOWS %s\n", _pk_domain_str(_tmp_domain_did), sys_name);

        }else{ //filter function exists
            PREPEND_TO_DEBUG_BUFFER(COLOR_CYAN " -- Domain %s is filtered by %p (installed in domain %s) to be run in domain %s\n",
                _pk_domain_str(filteree_did),
                domain_filter->filter,
                _pk_domain_str(_tmp_domain_did),
                _pk_domain_str(domain_filter->filter_did));
        }

        //check parent next:
        if(_tmp_domain->parent_did != DID_INVALID){
            PREPEND_TO_DEBUG_BUFFER(COLOR_CYAN " -- Checking Parent (%s) next.\n", _pk_domain_str(_tmp_domain->parent_did));
            assert_ifdebug(_tmp_domain->parent_did < NUM_DOMAINS);
            _tmp_domain_did = _tmp_domain->parent_did;
            _tmp_domain = &pk_data.domains[_tmp_domain->parent_did];
            assert_ifdebug(_tmp_domain->used);
            continue;
        }else{
            //PREPEND_TO_DEBUG_BUFFER(COLOR_CYAN " -- Domain %s has no parent, checking monitor filters\n", _pk_domain_str(_tmp_domain_did));
            switch ((uint64_t)monitor_filter->filter){
                case (uint64_t)SYSCALL_ALLOWED:      PREPEND_TO_DEBUG_BUFFER(COLOR_CYAN " -- monitor ALLOWS %s\n", sys_name); break;
                case (uint64_t)SYSCALL_DENIED:       PREPEND_TO_DEBUG_BUFFER(COLOR_CYAN " -- monitor DENIES %s\n", sys_name); break;
                case (uint64_t)SYSCALL_UNSPECIFIED:  PREPEND_TO_DEBUG_BUFFER(COLOR_CYAN " -- unspecified %s\n", sys_name); break;
                default:                             PREPEND_TO_DEBUG_BUFFER(COLOR_CYAN " -- monitor runs filter %p\n", monitor_filter->filter); break;
            }
            break; //break out of while loop
        }
    }
    //PREPEND_TO_DEBUG_BUFFER(COLOR_CYAN "-------------------------------\n");
}
//------------------------------------------------------------------------------

PK_CODE_INLINE void _sf_init_ti(trace_info_t* ti, int filteree_did, long syscall_nr, void* filter, void* mem, size_t mem_offset) {
#ifndef RELEASE
            memset(ti, 0, sizeof(trace_info_t));
#endif
            ti->flags         = 0;
            if (DID_INVALID  != _sf_impersonate) {
                ti->did       = _sf_impersonate;
            } else {
                ti->did       = filteree_did;
            }
            ti->syscall_nr    = syscall_nr;
            // args
            // orig_args
            ti->return_value  = -1;

            ti->filter        = filter;

            ti->mem           = mem;
            ti->mem_offset    = mem_offset;

            //ti->pid = -1;
            //ti->filter_syscalls = 1;
            //arch_regs
}
//------------------------------------------------------------------------------

PK_CODE_INLINE void _sf_init_syscall(_pk_syscall* syscall, trace_info_t* ti, pkru_config_t filter_config, int flags, int filteree_did, uint64_t* filteree_stack, void* filteree_reentry) {
    assert_ifdebug(syscall->filter_info == NULL);
    assert_ifdebug(syscall->flags == 0);
    assert_ifdebug(syscall->filter_mem != NULL);
    assert_ifdebug(syscall->filteree_reentry == NULL);

    syscall->filter_info      = ti;
    // We keep filter_mem as is
    syscall->filter_config    = filter_config;
    syscall->flags            = flags;
    syscall->filteree_did     = filteree_did;
#ifndef RELEASE
    syscall->filteree_stack   = filteree_stack;
#endif
    syscall->filteree_reentry = filteree_reentry;
}
//------------------------------------------------------------------------------

PK_CODE_INLINE void _sf_deinit_syscall(_pk_syscall* syscall) {
    syscall->filter_info      = NULL;
    // We keep filter_mem as is
    syscall->filter_config    = INT_TO_PKRU(0);
    syscall->flags            = 0;
    syscall->filteree_did     = DID_INVALID;
#ifndef RELEASE
    syscall->filteree_stack   = NULL;
#endif
    syscall->filteree_reentry = 0;
}
//------------------------------------------------------------------------------

PK_CODE_INLINE long _sf_monitor_syscall_handler(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long unused, long nr, long* dofilter)
{
    assert_ifdebug(pk_trusted_tls.init);

    PREPEND_TO_DEBUG_BUFFER("%s", ""); // for DEBUG_TIME
    long return_value = -1;
    _pk_acquire_lock();

    #if 1
    if(nr != SYS_write){
        FLUSH_DEBUG_BUFFER();
    }
    #endif

#ifndef RELEASE
    //debugging: check if data around sf_table was corrupted
    _pk_domain * dom = &pk_data.domains[CURRENT_DID];
    for (size_t i = 0; i < sizeof(dom->padding1); i++)
    {
        assert(dom->padding1[i] == (char)i);
        assert(dom->padding2[i] == (char)i);
    }
#endif

    assert_ifdebug(!pk_trusted_tls.filter_syscalls);

    int filteree_did = CURRENT_DID;
    assert(nr >= 0 && nr < NUM_DOMAIN_FILTERS);
    assert_ifdebug(filteree_did != DID_INVALID);
    assert_ifdebug(filteree_did < NUM_DOMAINS);
    assert_ifdebug(pk_data.domains[filteree_did].used);

    sysent_t * monitor_filter = &sf_table[nr];

    PREPEND_TO_DEBUG_BUFFER("_sf_monitor_syscall_handler(%lu = %s). did=%s. ", nr, sysno_to_str(nr), _pk_domain_str(CURRENT_DID));
    PREPEND_TO_DEBUG_BUFFER("args = 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx\n", arg0, arg1, arg2, arg3, arg4, arg5);
    if(DID_INVALID != _sf_impersonate){
        PREPEND_TO_DEBUG_BUFFER(COLOR_YELLOW "Attempting to impersonate syscall for %s\n", _pk_domain_str(_sf_impersonate));
        if (!_domain_is_descendant(_sf_impersonate)) {
            PREPEND_TO_DEBUG_BUFFER(COLOR_YELLOW "Impersonate did is not a descendant!\n");
            goto deny;
        }
    }
    #ifdef __riscv
        PREPEND_TO_DEBUG_BUFFER("uepc = 0x%lx\n", CSRR(CSR_UEPC));
    #endif


    #ifndef RELEASE
    //print flow before actually doing it
    _print_flow(nr);
    #endif


    int          tmp_domain_did = filteree_did; //convenience variable so that we dont have to do (tmp_domain-pk_data.domains)/sizeof(_pk_domain)
    _pk_domain * tmp_domain     = &pk_data.domains[tmp_domain_did];
    while(true){
        // check for filters in domain
        filter_compact_t * domain_filter = &tmp_domain->sf_table[nr];
        assert_ifdebug(domain_filter->filter != SYSCALL_UNSPECIFIED);
        if((void*)domain_filter->filter == SYSCALL_DENIED){
            ERROR(" * domain %s DENIES the syscall %s", _pk_domain_str(tmp_domain_did), sysno_to_str(nr));
            goto deny;
        }
        else if(domain_filter->filter == SYSCALL_ALLOWED){
            //domain allows syscall, check parent next:
            if(tmp_domain->parent_did != DID_INVALID){
                assert_ifdebug(tmp_domain->parent_did < NUM_DOMAINS);
                tmp_domain_did = tmp_domain->parent_did;
                tmp_domain = &pk_data.domains[tmp_domain_did];
                assert_ifdebug(tmp_domain->used);
                continue;
            }

            //reached "root", check for monitor filters
            switch ((uint64_t)monitor_filter->filter){
                case (uint64_t)SYSCALL_ALLOWED:
                    PREPEND_TO_DEBUG_BUFFER(" * monitor ALLOWS the syscall\n");

                    return_value = _sf_do_syscall_impersonate(filteree_did, nr, arg0, arg1, arg2, arg3, arg4, arg5);
                    goto end;
                case (uint64_t)SYSCALL_DENIED:
                    ERROR(" * monitor DENIES syscall %s", sysno_to_str(nr));
                    goto deny;
                    break;
                default:
                    //run monitor filter
                    PREPEND_TO_DEBUG_BUFFER(" * monitor runs filter %p\n", monitor_filter->filter);
                    _pk_thread_domain* filteree_thread_domain = _pk_get_thread_domain_data_nodidcheck(filteree_did);
                    assert_ifdebug(filteree_thread_domain->syscall.filter_mem != NULL);

                    trace_info_t ti;
                    _sf_init_ti(&ti, filteree_did, nr, NULL, filteree_thread_domain->syscall.filter_mem, 0);
                    _sf_set_ti_args(&ti, arg0, arg1, arg2, arg3, arg4, arg5);

                    if (sf_arg_copy_syscall_enter(&ti, monitor_filter->arg_copy) == -1) {
                        // revert previous changes
                        return_value = -errno;
                        goto end;
                    }

                    _sf_impersonate = DID_INVALID; // Every filter function is entered with a clean sf_impersonate_
                                                   // It needs to assign ti->did to _sf_impersonate itself, if required

                    if (monitor_filter->filter == SYSCALL_UNSPECIFIED) {
                        ERROR_FAIL("unhandled syscall %3ld '%s'", nr, sysno_to_str(nr));
                    }
                    assert_ifdebug((long)monitor_filter->filter > 0);

                    // lock needs to be released for ENTER and EXIT, filters
                    // else locks, that are acquired in ENTER and released in EXIT may produce deadlocks
                    _pk_release_lock();
                    monitor_filter->filter(&ti);
                    if (IS_SYSCALL_ALLOWED(&ti)) {
                        _sf_impersonate = ti.did;

                        _pk_acquire_lock();
                        // releases lock internally, but uses donky data structures
                        ti.return_value = _sf_do_syscall_impersonate(filteree_did, ti.syscall_nr, ti.args[0], ti.args[1], ti.args[2], ti.args[3], ti.args[4], ti.args[5]);
                        _pk_release_lock();

                        _sf_impersonate = DID_INVALID;
                        SET_SYSCALL_EXIT(&ti);
                        monitor_filter->filter(&ti);
                    }

                    _pk_acquire_lock();
                    // also restore args for filters that don't execute the syscall
                    if (sf_arg_copy_syscall_exit(&ti, monitor_filter->arg_copy) == -1) {
                        return_value = -errno;
                        goto end;
                    }
                    return_value = ti.return_value;
                    goto end;
            }
            assert(false); //unreachable
        }else{ //filter function exists
            PREPEND_TO_DEBUG_BUFFER(" * domain %s is filtered by %p (installed in domain %s) to be run in domain %s\n",
                _pk_domain_str(filteree_did),
                domain_filter->filter,
                _pk_domain_str(tmp_domain_did),
                _pk_domain_str(domain_filter->filter_did)
            );

            int filter_did = domain_filter->filter_did;
            _pk_thread_domain* filter_thread_domain = _pk_get_thread_domain_data_nodidcheck(filter_did);

            _pk_thread_domain* filteree_thread_domain = _pk_get_thread_domain_data_nodidcheck(filteree_did);
            // Since we're about to switch domains, we need to save the user stack
#ifndef RELEASE            
            uintptr_t* filteree_stack = SYSCALL_STACK; //backup filteree stack
#else
            uintptr_t* filteree_stack = NULL;
#endif
            filteree_thread_domain->user_stack = SYSCALL_STACK;
            
#ifdef __x86_64__
            assert(((uintptr_t)filteree_thread_domain->user_stack % 16) == 0);
#endif

            // Load target stack pointer
            uint64_t * target_stack = (uint64_t *) GET_USER_STACK(filter_thread_domain);

#ifdef __x86_64__
            assert_ifdebug(((uintptr_t)target_stack % 16) == 0); // target_stack must be aligned
#endif
            assert_ifdebug(target_stack != 0);

            // Check if there's enough space on target stack for pushing trace_info_t
            if(unlikely(!_user_stack_push_allowed(filter_thread_domain, (uintptr_t)target_stack, sizeof(trace_info_t)))) {
                errno = ENOSPC;
                ERROR_FAIL("invalid target stack pointer, or not enough space");
            }

            // pushing ti struct onto target stack
            trace_info_t * ti = ((trace_info_t *)target_stack) - 1;
            target_stack = (uint64_t*)ti;

#ifdef __x86_64__
            assert_ifdebug(((uintptr_t)target_stack % 16) == 8); // we intentionally misalign it for _pk_domain_switch
#endif

            _sf_init_ti(ti, filteree_did, nr, domain_filter->filter, filteree_thread_domain->syscall.filter_mem, 0);
            _sf_set_ti_args(ti, arg0, arg1, arg2, arg3, arg4, arg5);

            pkru_config_t filter_config = read_pkru_current_thread(filter_did);
            _pk_syscall *syscall = &filter_thread_domain->syscall;
            _sf_init_syscall(syscall, ti, filter_config, domain_filter->flags, filteree_did, filteree_stack, SYSCALL_REENTRY);

            // copy syscall arguments
            syscall->filter_arg_copy = domain_filter->arg_copy;
            if (sf_arg_copy_syscall_enter(ti, domain_filter->arg_copy) == -1) {
                // Revert previous changes
                _sf_deinit_syscall(syscall);
                filteree_thread_domain->user_stack = NULL;
                return_value = -errno;
                goto end;
            }

            //We want to have the following keys loaded:
            // * default key for filter domain
            // * RO key for pk-data strucutres
            // * syscall args key (even if it is not owned by filter_did!!

            // We always use syscall->filter_mem and syscall_args_key of filteree_did (and not of _sf_impersonate)
            // since this one is guaranteed to be free

            if (unlikely(0 != _pk_domain_load_pkkey_unlocked(filter_did, &pk_trusted_tls.syscall_args_key, PK_SLOT_ANY))) {
                ERROR_FAIL("unable to load syscall_args_key");
            }

            _pk_domain_switch(TYPE_SYSCALL_FILTER, filter_did, _sf_domain_syscall_handler, target_stack);

            // Indicate to assembler code that we now jump into filter code and do not return to the original caller
            if (dofilter) { *dofilter = 1; }

            assert_ifdebug( _pk_is_pkey_loaded_arch(pk_trusted_tls.syscall_args_key.pkey, read_pkru_current_thread(filter_did)) );
            assert_ifdebug( _pk_is_pkey_loaded_arch(rokey_for_exception_handler.pkey,                     read_pkru_current_thread(filter_did)) );

            // return value is stored in a0 -> gets first argument in function called after uret (= sf_domain_syscall_handler)
            return_value = (long)syscall->filter_info;
            goto end;

        }
        assert(false); //unreachable
    } // while

    assert(false); //unreachable code
    //--------------------------------------------------------------------------
deny:
        PREPEND_TO_DEBUG_BUFFER("domain denying %s(%lu, %lu, %lu, %lu, %lu, %lu)\n", sysno_to_str(nr), arg0, arg1, arg2, arg3, arg4, arg5);
        return_value = -EPERM;
end:
        _pk_release_lock();
        return return_value;
}
//------------------------------------------------------------------------------

#ifdef __x86_64__
PK_CODE long sf_monitor_syscall_handler_x86_64(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long nr, long* dofilter)
{
    return _sf_monitor_syscall_handler(arg0, arg1, arg2, arg3, arg4, arg5, 0, nr, dofilter);
}
//------------------------------------------------------------------------------
#else
PK_CODE long sf_monitor_syscall_handler_riscv(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long unused, long nr)
{
    return _sf_monitor_syscall_handler(arg0, arg1, arg2, arg3, arg4, arg5, unused, nr, NULL);
}
//------------------------------------------------------------------------------
#endif

PK_CODE long sf_monitor_syscall_exit_handler()
{
    _pk_acquire_lock();

    int filter_did = CURRENT_DID;
    _pk_thread_domain* filter_thread_domain = _pk_get_thread_domain_data_nodidcheck(filter_did);
    _pk_syscall * syscall = &filter_thread_domain->syscall;
    int filteree_did = syscall->filteree_did;

    long return_value = syscall->filter_info->return_value;
    trace_info_t *ti = syscall->filter_info;
    if (sf_arg_copy_syscall_exit(ti, syscall->filter_arg_copy) == -1) {
        return_value = -errno;
    }

    PREPEND_TO_DEBUG_BUFFER("filter_did = %s, ", _pk_domain_str(filter_did));
    PREPEND_TO_DEBUG_BUFFER("filteree_did = %s, ", _pk_domain_str(filteree_did));
    if (/*syscall->filter_info == 0 ||*/ syscall->filteree_reentry == 0) {
        ERROR_FAIL("Thread is not expecting a syscall exit");
    }
    PREPEND_TO_DEBUG_BUFFER("switching to did=%s, entry=%p, return=%ld\n", _pk_domain_str(filteree_did), syscall->filteree_reentry, syscall->filter_info->return_value);

    pkru_config_t filter_config = syscall->filter_config;
    write_pkru_current_thread(filter_did, filter_config);
    assert_ifdebug( ! _pk_is_pkey_loaded_arch(pk_trusted_tls.syscall_args_key.pkey, read_pkru_current_thread(filter_did)) );

    // Restore filteree context
    _pk_thread_domain* filteree_thread_domain = _pk_get_thread_domain_data_nodidcheck(filteree_did);
    // misusing TYPE_SYSCALL_RET (set UEPC in riscv, don't set filteree_reentry in x86 as it is already on the stack)
    uint64_t* filteree_stack = GET_USER_STACK(filteree_thread_domain);
    assert_ifdebug(filteree_stack == syscall->filteree_stack);
    _pk_domain_switch(TYPE_SYSCALL_RET, filteree_did, syscall->filteree_reentry, filteree_stack);
    _sf_deinit_syscall(syscall);

    _pk_release_lock();
    return return_value;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// ATTENTION! Below code is executed in domain, not in monitor
//------------------------------------------------------------------------------

FORCE_INLINE long _sf_syscall_libc_ti(trace_info_t * ti)
{
    long return_value = syscall(ti->syscall_nr, ti->args[0], ti->args[1], ti->args[2], ti->args[3], ti->args[4], ti->args[5]);
    // libc wrapper sets errno
    // We need to undo this since we have intercepted the syscall in its original libc wrapper
    // which itself will set errno
    if (-1 == return_value) {
        return -errno;
    } else {
        return return_value;
    }
}
//------------------------------------------------------------------------------

void sf_domain_syscall_handler(trace_info_t *ti)
{
    assert_ifdebug(ti);
    assert_ifdebug(ti->filter);

    DEBUG_FILTER();
    //static buffer of pk_sprint_reg_arch seems inaccessible
    //PREPEND_TO_DEBUG_BUFFER("sf_domain_syscall_handler: current pkru = %s\n", pk_sprint_reg_arch(_read_pkru_reg()));

    SET_SYSCALL_ENTER(ti);
    _sf_impersonate = DID_INVALID; // Every filter function is entered with a clean sf_impersonate_
                                   // It needs to assign ti->impersonate_did to sf_impersonate_ itself, if required

    if (ti->filter == SYSCALL_UNSPECIFIED) {
        ERROR_FAIL("unhandled syscall %3ld '%s'", ti->syscall_nr, sysno_to_str(ti->syscall_nr));
    }
    assert_ifdebug((long)ti->filter > 0);

    // ti is on stack of filter domain -> syscall of filteree cannot perform a boomerang attack
    SET_SYSCALL_ENTER(ti);
    ti->filter(ti);
    if (IS_SYSCALL_ALLOWED(ti)) {
        _sf_impersonate = ti->did;
        ti->return_value = _sf_syscall_libc_ti(ti);
        _sf_impersonate = DID_INVALID;

        SET_SYSCALL_EXIT(ti);
        ti->filter(ti);
    }

    PREPEND_TO_DEBUG_BUFFER("sf_domain_syscall_handler: end\n");
}
//------------------------------------------------------------------------------
