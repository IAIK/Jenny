#include "pk_internal.h"
#include "mprotect.h"

//------------------------------------------------------------------------------
#ifdef FAKE_MPK_REGISTER
pkru_config_t emulated_mpk_reg;
#endif /* FAKE_MPK_REGISTER */
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// Public API functions
//------------------------------------------------------------------------------
extern unsigned char pk_initialized;
int __attribute__((naked)) pk_do_init(int flags, void* arg1, void* arg2){
    asm volatile (
        // call _pk_init, remember old ra
        "addi     sp,sp,-8;"
        "sd       ra,0(sp);" //save ra
        "call     _pk_init;"

        //set pk_initialized to 1
        "la       ra, %[initialized];" //temporarily misuse ra register for address of pk_initialized
        "li       a1, 1;"
        "sb       a1, 0(ra);" //pk_initialized = 1;


        "ld       ra,0(sp);" //restore ra
        "addi     sp,sp,8;"  //remove stack frame

        //Set uepc to ra (previous return address)
        //and do a uret, such that we lock ourselves out.
        //"csrrw zero, %1, ra;"
        "csrrw zero, %[uepc], ra;"
        "uret;"

        :  : [initialized] "X"(&pk_initialized), [uepc] "i"(CSR_UEPC)
    );
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Internal untrusted functions
//------------------------------------------------------------------------------
int _pk_halt() {
  ERROR("_pk_halt: No exception handler installed. Do not know how to proceed!");
  _pk_print_debug_info();
  print_maps();
  assert(false);
}

//------------------------------------------------------------------------------
// Internal trusted functions
//------------------------------------------------------------------------------
int PK_CODE _pk_init_arch() {

    uint64_t misa = CSRR(CSR_UMISA);
    char misa_str[27] = {0, };
    char* str_p = misa_str;
    for (size_t i = 0; i < 26; i++) {
        if ( misa & (1 << i) ) {
            *str_p++ = 'a' + i;
        }
    }
    DEBUG_MPK("misa = %zx = %s", misa, misa_str);
    assert( misa & (1 << ('u' - 'a')) );
    assert( misa & (1 << ('s' - 'a')) );
    assert( misa & (1 << ('i' - 'a')) );
    assert( misa & (1 << ('m' - 'a')) );
    assert( misa & (1 << ('a' - 'a')) );
    assert( misa & (1 << ('c' - 'a')) );
    assert( misa & (1 << ('n' - 'a')) );

    //check if utvec table is protected
#ifndef SHARED
    DEBUG_MPK("pk_utvec_table  = %p", ((char*)&pk_utvec_table));
    assert( ((uintptr_t*)&pk_utvec_table) >= __start_pk_all);
    assert( ((uintptr_t*)&pk_utvec_table) < __stop_pk_all);
    assert( ((uintptr_t*)&pk_utvec_table) >= __start_pk_code);
    assert( ((uintptr_t*)&pk_utvec_table) < __stop_pk_code);
#endif

    // check pkru register
    pkru_config_t reg = _read_pkru_reg();

#ifndef FAKE_MPK_REGISTER
    assert(reg.mode == 1);
#endif

    //reset pkru
    reg = read_pkru_current_thread(_pk_current_did());
    assert(reg.sw_did == DID_FOR_ROOT_DOMAIN ||
           reg.sw_did == DID_FOR_CHILD_DOMAIN);
    assert(reg.mode == 1);
    _write_pkru_reg(reg);
    DEBUG_MPK("_pk_init_arch end");
    return 0;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// Internal functions
//------------------------------------------------------------------------------

void PK_CODE _pk_setup_exception_stack_arch(void* exception_stack) {
    pk_trusted_tls.exception_stack_base = exception_stack;
    pk_trusted_tls.exception_stack = (uint64_t*)exception_stack + EXCEPTION_STACK_WORDS - 2;
    //-2 because the stack must be aligned by 128-bit according to the RISC-V psABI spec
    assert_warn(CSRR(CSR_USCRATCH) == 0);
    CSRW(CSR_USCRATCH, pk_trusted_tls.exception_stack);
}
//------------------------------------------------------------------------------

void PK_CODE _pk_setup_exception_handler_arch() {
    // Note: lowest bit must be set to use vectored exceptions
    uint64_t utvec_addr = (uint64_t)&pk_utvec_table;

    //Check alignment. see comment where pk_utvec_tableis defined.
    uint64_t alignment = 0;
    while((utvec_addr >> (alignment+1)) << (alignment+1) == utvec_addr){
        alignment++;
    };
    DEBUG_MPK("pk_utvec_table = 0x%zx. alignment = %zu bits", utvec_addr, alignment);
    assert( alignment >= 8 );

    uint64_t utvec = utvec_addr | 1;
    assert_warn(CSRR(CSR_UTVEC) == 0);
    CSRW(CSR_UTVEC, utvec);
}
//------------------------------------------------------------------------------

pkru_config_t PK_CODE _pk_create_default_config_arch(int did) {
    DEBUG_MPK("_pk_create_default_config_arch(did=%d)", did);
    assert_ifdebug(_domain_exists(did));

    pkru_config_t config = {0, };
    // set default reg value
    // Note: setting mode to 1, otherwise we'd lock ourselves out
    // when we write the register. Mode will be set to zero with the
    // uret instruction
    config.mode         = 1;
    config.sw_did       = did;
    if (did == DID_FOR_EXCEPTION_HANDLER){
        return config;
    }

    //the key only gets set for normal domains
    //otherwise we'd still have the exception handler's key loaded when
    //returning to "the root" where the exception handler was registered
    pk_key_t keys_to_be_used_for_default_config[4] = {0};
    int default_keys_index = 0;
    for(size_t key_index = 0; key_index < NUM_KEYS_PER_DOMAIN && default_keys_index <= 3; key_index++){
        pk_key_t key = pk_data.domains[did].keys[key_index];
        if(! key.used){
            continue;
        }
        keys_to_be_used_for_default_config[default_keys_index] = key;
        //ERROR("keys_to_be_used_for_default_config[default_keys_index].pkey = %d", keys_to_be_used_for_default_config[default_keys_index].pkey);
        //ERROR("keys_to_be_used_for_default_config[default_keys_index].vkey = %d", keys_to_be_used_for_default_config[default_keys_index].vkey);
        //ERROR("keys_to_be_used_for_default_config[default_keys_index].perm = %d", keys_to_be_used_for_default_config[default_keys_index].perm);
        //ERROR("");
        default_keys_index++;
    }
    //NOTE: we cannot use _pk_domain_load_key_arch since it also writes the value to as default_config for current_thread instead of merely returning it

    assert_ifdebug(keys_to_be_used_for_default_config[0].used); //at least the default key should already exist for this domain

    //NOTE: keys_to_be_used_for_default_config might not be fully initialized if the domain doesn't have that many keys
    //      in this case it's 0, which is fine.
    config.slot_0_mpkey = keys_to_be_used_for_default_config[0].pkey;
    config.slot_1_mpkey = keys_to_be_used_for_default_config[1].pkey;
    config.slot_2_mpkey = keys_to_be_used_for_default_config[2].pkey;
    config.slot_3_mpkey = keys_to_be_used_for_default_config[3].pkey;

    config.slot_0_wd    = (keys_to_be_used_for_default_config[0].perm & PKEY_DISABLE_WRITE) ? 1 : 0;
    config.slot_1_wd    = (keys_to_be_used_for_default_config[1].perm & PKEY_DISABLE_WRITE) ? 1 : 0;
    config.slot_2_wd    = (keys_to_be_used_for_default_config[2].perm & PKEY_DISABLE_WRITE) ? 1 : 0;
    config.slot_3_wd    = (keys_to_be_used_for_default_config[3].perm & PKEY_DISABLE_WRITE) ? 1 : 0;

    //update previous slot number such that we dont immediately evict those keys again
    pk_trusted_tls.thread_dom_data[did].previous_slot = default_keys_index - 1;
    //ERROR("previous_slot %d", pk_data.domains[did].previous_slot);

    //sanity checks
    assert_ifdebug(config.mode   == 1);
    assert_ifdebug(config.sw_did == did);

    //DEBUG_MPK("config = %s", pk_sprint_reg_arch(config));

    return config;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_load_key_arch(int did, pkey_t pkey, int slot, int perm) {
    DEBUG_MPK("_pk_domain_load_key_arch(%d, %u, %d %s, %d)", 
        did,
        pkey,
        slot,
        slot == PK_SLOT_NONE ? "PK_SLOT_NONE" : (slot == PK_SLOT_ANY ? "PK_SLOT_ANY" : ""),
        perm
    );
    //int slot_initial_argument = slot;

    assert_ifdebug(pkey > 0 && pkey < PK_NUM_KEYS);

    if (slot != PK_SLOT_ANY && slot != PK_SLOT_NONE) {
        ERROR("Invalid slots");
        errno = EINVAL;
        return -1;
    }

    if ( perm & ~(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE) ) {
        ERROR("Invalid permissions. Only supports PKEY_DISABLE_ACCESS and PKEY_DISABLE_WRITE");
        errno = EINVAL;
        return -1;
    }

    if (PK_SLOT_NONE == slot) {
        // By disabling access, key is unloaded
        perm = PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE;
    }

    pkru_config_t pkru_old = read_pkru_current_thread(did);
    DEBUG_MPK("config reg for domain %d: %s\n", did, pk_sprint_reg_arch(pkru_old));

    //sanity checks
    assert_ifdebug(pkru_old.sw_did    == did);
    assert_ifdebug(pkru_old.mode      == 1);

    // try to reuse existing pkey
    if      (pkru_old.slot_0_mpkey == pkey) { slot = 0; } 
    else if (pkru_old.slot_1_mpkey == pkey) { slot = 1; } 
    else if (pkru_old.slot_2_mpkey == pkey) { slot = 2; } 
    else if (pkru_old.slot_3_mpkey == pkey) { slot = 3; }

    if (slot == PK_SLOT_NONE){
        DEBUG_MPK("Key not loaded. Nothing to do");
        return 0;
    }

    if (PK_SLOT_ANY == slot) {
        //get actual slot number
        int * previous_slot = &(pk_trusted_tls.thread_dom_data[did].previous_slot);
        //ERROR("previous_slot %d", *previous_slot);
        slot = (*previous_slot % 3) + 1; //0th slot is always the default key
        *previous_slot = slot;
        DEBUG_MPK("Updating slot %d", slot);
    } else {
        DEBUG_MPK("Reusing slot %d", slot);
    }

    // prepare new pkru value
    int wd = (perm & PKEY_DISABLE_WRITE) ? 1 : 0;
    uint64_t key_mask = (uint64_t)0b11111111111ULL << (slot * 11);
    uint64_t key_val  = (uint64_t)((uint64_t)pkey | ((uint64_t)wd << 10)) << (slot * 11);

    //0th slot is always the default key. 
    //if(slot_initial_argument != PK_SLOT_NONE){
    //    assert_ifdebug((slot > 0 && slot < 4) || (slot == 0 && pkru_old.slot_0_wd == wd));
    //}
    // slot 0 is (only) allowed if nothing would change
    //Because for some reason assign_key is called (by our tests) with the key that's already in slot 0
    //NOTE: slot 0 is also used when freeing a domain

    // erase key slot
    uint64_t      tmp = PKRU_TO_INT(pkru_old) & ~key_mask;

    if (!(perm & PKEY_DISABLE_ACCESS)) {
      // set new protection key
      tmp |= key_val;
    }
    pkru_config_t pkru_new = INT_TO_PKRU(tmp);

    assert_ifdebug(pkru_new.mode      == pkru_old.mode);
    assert_ifdebug(pkru_new.sw_did    == pkru_old.sw_did);
    assert_ifdebug(pkru_new.sw_unused == pkru_old.sw_unused);

    DEBUG_MPK("Updating PKRU from %s", pk_sprint_reg_arch(pkru_old));
    DEBUG_MPK("to                 %s", pk_sprint_reg_arch(pkru_new));

    if (perm & PKEY_DISABLE_ACCESS) {
      assert_ifdebug( ! _pk_is_pkey_loaded_arch(pkey, pkru_new));
    } else {
      //checking bit-mask magic
      assert_ifdebug((slot == 0 && pkru_new.slot_0_mpkey == pkey && pkru_new.slot_0_wd == wd) || pkru_new.slot_0_mpkey == pkru_old.slot_0_mpkey);
      assert_ifdebug((slot == 0 && pkru_new.slot_0_mpkey == pkey && pkru_new.slot_0_wd == wd) || pkru_new.slot_0_wd    == pkru_old.slot_0_wd);
      assert_ifdebug((slot == 1 && pkru_new.slot_1_mpkey == pkey && pkru_new.slot_1_wd == wd) || pkru_new.slot_1_mpkey == pkru_old.slot_1_mpkey);
      assert_ifdebug((slot == 1 && pkru_new.slot_1_mpkey == pkey && pkru_new.slot_1_wd == wd) || pkru_new.slot_1_wd    == pkru_old.slot_1_wd);
      assert_ifdebug((slot == 2 && pkru_new.slot_2_mpkey == pkey && pkru_new.slot_2_wd == wd) || pkru_new.slot_2_mpkey == pkru_old.slot_2_mpkey);
      assert_ifdebug((slot == 2 && pkru_new.slot_2_mpkey == pkey && pkru_new.slot_2_wd == wd) || pkru_new.slot_2_wd    == pkru_old.slot_2_wd);
      assert_ifdebug((slot == 3 && pkru_new.slot_3_mpkey == pkey && pkru_new.slot_3_wd == wd) || pkru_new.slot_3_mpkey == pkru_old.slot_3_mpkey);
      assert_ifdebug((slot == 3 && pkru_new.slot_3_mpkey == pkey && pkru_new.slot_3_wd == wd) || pkru_new.slot_3_wd    == pkru_old.slot_3_wd);
      // pkey is loaded exactly once
      assert_ifdebug((pkru_new.slot_0_mpkey == pkey) + (pkru_new.slot_1_mpkey == pkey) + (pkru_new.slot_2_mpkey == pkey) + (pkru_new.slot_3_mpkey == pkey) == 1);
    }

    //update register
    write_pkru_current_thread(did, pkru_new);
    return 0;
}
//------------------------------------------------------------------------------

// Ensure that _expected_return stack is not 16-byte but 8-byte aligned
// This ensures that user stack gets 16-byte aligned for psabi
// See _pk_exception_handler_arch_c
C_STATIC_ASSERT((sizeof(_expected_return) % 16) == 8);
C_STATIC_ASSERT((sizeof(_return_did)      % 16) == 8);

uint64_t PK_CODE _pk_exception_handler_arch_c(uint64_t data, uint64_t id, uint64_t type){
#if defined(TIMING) && TIMING_HANDLER_C != 0
    if(type == TIMING_HANDLER_C_TYPE)
        TIME_START(TIMING_HANDLER_C);
#endif

    uint64_t ret = type;

    _pk_acquire_lock();

    DEBUG_MPK("_pk_exception_handler_arch_c(data=%zu, id=%zu, type=%zu=%s) uepc=0x%lx, utval=0x%lx, ucause=0x%lx, uscratch=0x%lx", 
        data, id, type, type_str(type),
        CSRR(CSR_UEPC), CSRR(CSR_UTVAL), CSRR(CSR_UCAUSE), CSRR(CSR_USCRATCH));

    #ifdef ADDITIONAL_DEBUG_CHECKS
        //register uint64_t* sp asm("sp");
        //assert(sp >= pk_data.exception_stack && sp < EXCEPTION_STACK_TOP);
        assert_warn(CSRR(CSR_UCAUSE) == CAUSE_MPKEY_MISMATCH_FAULT);
        assert_warn(_read_pkru_reg().mode == 1);

        //this is already asserted in assembly
        assert(type == TYPE_EXCEPTION || (void*)CSRR(CSR_UTVAL) == &_pk_exception_handler);

        //if(type != TYPE_CALL && type != TYPE_RET){
        //    PRINT_UREGS();
        //}
    #endif

    uint64_t * stack_of_caller = (uint64_t*)CSRR(CSR_USCRATCH);
    void * reentry = (void*)CSRR(CSR_UEPC);

    /*
    #ifdef ADDITIONAL_DEBUG_CHECKS
	//check for correct stack alignment
        if (type == TYPE_CALL) {
            assert((reentry % 16) == 8); // check stack misaligned
        }else{
            assert(((uintptr_t)stack_of_caller % 16) == 0); // check stack misaligned
        }
    #endif
    */


    if(unlikely(type == TYPE_EXCEPTION)){
        void * target_code = _pk_halt;
        void * bad_addr = (void*)CSRR(CSR_UTVAL);
        ret = 0;

        // Try to resolve key mismatch
        if (0 == _pk_exception_key_mismatch_unlocked(bad_addr)) {
            // key exception resolved
            ret = 0;
            goto end;
        }

        //Instead of halting, invoke user exception handler if it was registered.
        if (pk_data.user_exception_handler) {
            DEBUG_MPK("Invoking user exception handler");
            target_code = pk_data.user_exception_handler;
            //Call target code (without changing the current domain)
            _pk_domain_switch(TYPE_EXCEPTION, CURRENT_DID, target_code, stack_of_caller);
            // By returning a non-zero value, the assembler wrapper will
            // pass CSR_UTVAL in a0 to target_code
            ret = 1;
        }else{
            //(target_code == _pk_halt)
            //in this case the below code with _pk_domain_switch does not work
            //it would throw exceptions in an infinite loop because the current domain doesn't have access to the code of _pk_halt.
            //we could handle it like an API call, or simply call it directly
            _pk_halt();
            assert(false);
        }

    }else{
        _pk_exception_handler_unlocked(data, id, type, stack_of_caller, reentry);
    }

end:
    _pk_release_lock();

#if defined(TIMING) && TIMING_HANDLER_C != 0
    if(type == TIMING_HANDLER_C_TYPE)
        TIME_STOP(TIMING_HANDLER_C);
#endif

    return ret;
}
//------------------------------------------------------------------------------

void PK_CODE _pk_domain_switch_arch(int type, int target_did, pkru_config_t config, void* entry_point, uint64_t* target_stack) {
    DEBUG_MPK("_pk_domain_switch_arch(%d, %d, %p, %p)", type, target_did, entry_point, target_stack);
    pk_trusted_tls.current_did = target_did;

    //actual switch: write pkru,uepc,uscratch

    //write_pkru_current_thread(CURRENT_DID, config);
    _write_pkru_reg(config);

    CSRW(CSR_UEPC,     entry_point);
    CSRW(CSR_USCRATCH, target_stack);

    //check consistency of config
    assert_ifdebug(config.sw_did == target_did);
    assert_ifdebug(config.mode   == 1);
    //check if the domain-transition was successful
    assert_ifdebug(_pk_current_did() == target_did);
    //When returning to the root-domain, there should not be any old keys loaded
    //assert_ifdebug(target_did != 0 || CSRR(CSR_MPK) == 0x8000000000000000LL);
    //Default key for target domain should be loaded
    //ERROR("default key of did %d = %d", target_did, pk_data.domains[target_did].keys[0].pkey);
    //ERROR("pkru = %s", pk_sprint_reg_arch(config));
    //ERROR("pkru = %s", pk_sprint_reg_arch(_read_pkru_reg()));
    assert_ifdebug(_read_pkru_reg().slot_0_mpkey == pk_data.domains[target_did].keys[0].pkey);
}
//------------------------------------------------------------------------------

void PK_CODE _pk_pthread_exit(void* retval) {
  _pk_pthread_exit_c(retval);
}
//------------------------------------------------------------------------------

void* PK_CODE __attribute__((naked)) _pthread_init_function_asm(void *arg) {
  // We're entering here with the new user stack but in trusted mode
  // switch to trusted exception stack and call into C wrapper
  // Note: Using s0 as arg for start_routine because it's preserved across calls
  // Note s3 is also preserved across calls
  asm volatile(
    "mv  s3, a1\n"                    // save a1

    "ld  a0, %[start_routine]\n"      // save start_routine as first argument in a0
    "mv  a1, sp\n"                    // save current_user_stack as second argument a1
    "ld  sp, %[exception_stack]\n"    // load exception stack
    "ld  s0, %[_arg]\n"               // load *arg for start_routine into callee-saved register (s0)
    //"mv  s1, ra\n"                    // save ra to s1 (which is callee-saved)
    "call _pthread_init_function_c\n" // _pthread_init_function_c(start_routine, current_user_stack)
    "mv  a0, s0\n"                    // load *arg as first argument for start_routine
    //"mv  ra, s1\n"                    // restore ra which was previously saved to s1. it should probably point to pthread_exit or similar
    "la ra, pk_pthread_exit\n"           // For some reason the old ra doesnt work here, so we just set it to pthread_exit instead
    "mv  a1, s3\n"                    // restore a1

    "j _pk_exception_handler_end\n"
    : // no output operands
    : [start_routine]   "m"(pk_data.pthread_arg.start_routine),
      [exception_stack] "m"(pk_data.pthread_arg.exception_stack_top),
      [_arg]            "m"(pk_data.pthread_arg.arg)
    : "a0", "a1" // clobber these to prevent the compiler to use these for the input arguments
  );
}
//------------------------------------------------------------------------------

enum { //same order as in _pk_assert
    ra=0,
    t0,
    t1,
    t2,

    s0,
    s1,

    a0,
    a1,
    a2,
    a3,
    a4,
    a5,
    a6,
    a7,

    s2,
    s3,
    s4,
    s5,
    s6,
    s7,
    s8,
    s9,
    s10,
    s11,

    t3,
    t4,
    t5,
    t6,
    rend
};

#define _GET_VAL(r, stack) ((stack)[rend-1-(r)])
//#define PRINT_REG(r, stack) ERROR("%4s: 0x%016lx = %ld", #r, _GET_VAL(r, stack), _GET_VAL(r, stack))
#define PRINT_REG(r, stack) FPRINTF(stderr, COLOR_RED "%4s: 0x%016lx = %ld\n" COLOR_RESET, #r, _GET_VAL(r, stack), _GET_VAL(r, stack))

void PK_CODE __attribute__((noreturn)) _pk_assert_c(uintptr_t * assert_stack) {
    ERROR("_pk_assert_c DYING");
    PRINT_REG(ra,    assert_stack);
    PRINT_REG(t0,    assert_stack);
    PRINT_REG(t1,    assert_stack);
    PRINT_REG(t2,    assert_stack);

    PRINT_REG(s0,    assert_stack);
    PRINT_REG(s1,    assert_stack);

    PRINT_REG(a0,    assert_stack);
    PRINT_REG(a1,    assert_stack);
    PRINT_REG(a2,    assert_stack);
    PRINT_REG(a3,    assert_stack);
    PRINT_REG(a4,    assert_stack);
    PRINT_REG(a5,    assert_stack);
    PRINT_REG(a6,    assert_stack);
    PRINT_REG(a7,    assert_stack);

    PRINT_REG(s2,    assert_stack);
    PRINT_REG(s3,    assert_stack);
    PRINT_REG(s4,    assert_stack);
    PRINT_REG(s5,    assert_stack);
    PRINT_REG(s6,    assert_stack);
    PRINT_REG(s7,    assert_stack);
    PRINT_REG(s8,    assert_stack);
    PRINT_REG(s9,    assert_stack);
    PRINT_REG(s10,   assert_stack);
    PRINT_REG(s11,   assert_stack);

    PRINT_REG(t3,    assert_stack);
    PRINT_REG(t4,    assert_stack);
    PRINT_REG(t5,    assert_stack);
    PRINT_REG(t6,    assert_stack);
    ERROR("Additional info (maybe line number in pk_handler.S):");
    PRINT_REG(-2,    assert_stack); // info pushed by ASSERT_WITH_INFO

    assert(false);
}

