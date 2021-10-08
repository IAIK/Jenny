#pragma once
#include "pk_defs.h"

/**********************************************************************/
// Global Defines
/**********************************************************************/

#define THREAD_EXITING   ((void*)-1)
#define THREAD_UNUSED    NULL
// Max. number of ECALLs (over all domains)
#define NUM_REGISTERED_ECALLS 64

// Size of trusted exception stack slots
#ifdef RELEASE
// For debug output, give more stack
#define EXCEPTION_STACK_WORDS (1024*(PAGESIZE/WORDSIZE)) // 4MB
#else
#define EXCEPTION_STACK_WORDS (16*(PAGESIZE/WORDSIZE))   // 64KB
#endif // RELEASE

#define MAX_SIGNO           NSIG

// signal_pending
#define SIGNAL_DEFERRED       -1

// signal_state
#define SIGNAL_NONE   0
#define SIGNAL_ACTIVE 1
#define SIGNAL_RESUME 2

#define GET_STACK_TOP(DOMAIN_THREAD_DATA) ((uintptr_t)(DOMAIN_THREAD_DATA)->user_stack_base + ((DOMAIN_THREAD_DATA)->user_stack_size) - 2*WORDSIZE)
#define GET_USER_STACK(DOMAIN_THREAD_DATA) ((DOMAIN_THREAD_DATA)->user_stack ? (DOMAIN_THREAD_DATA)->user_stack : (uint64_t *)GET_STACK_TOP(DOMAIN_THREAD_DATA))

// Size of thread-local signal stack
#define PKU_SIGSTACK_SIZE_BYTES (4*PAGESIZE)

//------------------------------------------------------------------------------
//Defines for the API table
//NOTE this cannot be an enum because we need the values in assembly
#define _API_pk_my_debug_check             0
#define _API_pk_deinit                     1
#define _API_pk_current_did                2
#define _API_pk_register_exception_handler 3
#define _API_pk_api_generic                4
#define _API_pk_domain_create              5
#define _API_pk_domain_free                6
#define _API_pk_domain_release_child       7
#define _API_pk_set_binary_scanning        8
#define _API_unused9                       9
#define _API_pk_pkey_alloc                10
#define _API_pk_pkey_free                 11
#define _API_pk_pkey_mprotect             12
#define _API_pk_pkey_mprotect2            13
#define _API_unused14                     14
#define _API_unused15                     15
#define _API_unused16                     16
#define _API_unused17                     17
#define _API_unused18                     18
#define _API_unused19                     19
#define _API_pk_mmap                      20
#define _API_pk_mmap2                     21
#define _API_pk_mmap3                     22
#define _API_pk_munmap                    23
#define _API_pk_munmap2                   24
#define _API_pk_mprotect                  25
#define _API_pk_mprotect2                 26
#define _API_pk_madvise                   27
#define _API_pk_madvise2                  28
#define _API_pk_domain_register_ecall3    29
#define _API_pk_domain_register_ecall     30
#define _API_pk_domain_register_ecall2    31
#define _API_pk_domain_allow_caller       32
#define _API_pk_domain_allow_caller2      33
#define _API_pk_domain_assign_pkey        34
#define _API_pk_domain_default_key        35
#define _API_pk_domain_load_key           36
#define _API_unused37                     37
#define _API_unused38                     38
#define _API_unused39                     39
#define _API_pk_pthread_create            40
#define _API_pk_pthread_exit              41
#define _API_pk_print_debug_info          42
#define _API_pk_simple_api_call           43
#define _API_unused44                     44
#define _API_pk_sysfilter_domain          45
#define _API_pk_sysfilter_monitor         46
#define _API_pk_sysfilter_tracer          47
#define _API_pk_name_range                48
#define _API_pk_print_keys                49
#define _API_sf_filters_init              50
#define _API_sf_write_results             51
#define _API_pk_sigaction                 52
#define _API_pk_sigaction2                53
#define _API_pk_signal                    54
#define _API_pk_signal2                   55
#define _API_pk_sigaction_krnl2           56
#define API_TABLE_SIZE                    57 // must be exactly 1 more than the highest API id
//------------------------------------------------------------------------------

#define KEY_FOR_UNPROTECTED       0
//~ #define KEY_FOR_ROOT_DOMAIN       1
//~ #define KEY_FOR_EXCEPTION_HANDLER 2

#define DID_FOR_ROOT_DOMAIN       0
#define DID_FOR_EXCEPTION_HANDLER 1
#define DID_FOR_CHILD_DOMAIN      2

// Struct offset defines, required for assembler
#ifdef TLS_MISALIGNMENT_BUG
  #define TTLS_PADDING PAGESIZE
#else
  #define TTLS_PADDING 0
#endif
#define TTLS_OFFSET_BACKUP_USER_STACK      (TTLS_PADDING +  0)
#define TTLS_OFFSET_EXCEPTION_STACK        (TTLS_PADDING +  8)
#define TTLS_OFFSET_EXCEPTION_STACK_BASE   (TTLS_PADDING + 16)
#define ROTTLS_OFFSET_CURRENT_PKRU         (TTLS_PADDING + 24)
#define TTLS_OFFSET_FILTER_SYSCALLS        (TTLS_PADDING + 32)
#define TTLS_OFFSET_SIGNAL_PENDING         (TTLS_PADDING + 40)
#define TTLS_OFFSET_SIGNAL_STATE           (TTLS_PADDING + 44)
#define ROTTLS_OFFSET_BACKUP_PKRU          (TTLS_PADDING + 48)
#define TTLS_OFFSET_BACKUP_EXCEPTION_STACK (TTLS_PADDING + 56)
#define TTLS_OFFSET_ARGFRAME               (TTLS_PADDING + 64)

/**********************************************************************/
// Arch-specific
/**********************************************************************/

#include "pk_handler.h"

/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/

//#include "pk_debug.h"
#include "pk.h"
#include "sf_internal.h"
#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1 //Needed for pthread_getname_np and pthread_getattr_np and for link.h
#endif
#include <pthread.h>
#include "mprotect.h"

#ifdef __cplusplus
extern "C" {
#endif

//------------------------------------------------------------------------------
// C Defines
//------------------------------------------------------------------------------
#define C_STATIC_ASSERT(test) typedef char assertion_on_mystruct[( !!(test) )*2-1 ]

//------------------------------------------------------------------------------
// Linker symbols defined by linker_common.ld
//------------------------------------------------------------------------------
#ifndef SHARED
extern uintptr_t __start_pk_all[];
extern uintptr_t __stop_pk_all[];
extern uintptr_t __start_pk_data[];
extern uintptr_t __stop_pk_data[];
extern uintptr_t __start_pk_code[];
extern uintptr_t __stop_pk_code[];

extern uintptr_t __tls_static_start[];
extern uintptr_t __tls_static_end[];
#endif


//extern bool sf_data;
//------------------------------------------------------------------------------
// Generic PK typedefs
//------------------------------------------------------------------------------

/* Struct which is pushed on caller stack upon dcall, and verified upon dreturn */
typedef struct _expected_return {
    int      did;
    void *   reentry;
    void *   previous;
#ifdef ADDITIONAL_DEBUG_CHECKS
    void *   sp;
    uint64_t cookie;
#endif
#ifdef EXPECTED_RETURN_PADDING
    unsigned char padding[EXPECTED_RETURN_PADDING];
#endif
} _expected_return;
//------------------------------------------------------------------------------

/* Struct which is pushed on target stack upon dcall such that it knows where to return to */
typedef struct _return_did {
#ifdef ADDITIONAL_DEBUG_CHECKS
    uint64_t cookie1;
#endif
    int64_t did;
#ifdef ADDITIONAL_DEBUG_CHECKS
    uint64_t cookie2;
#endif
} _return_did;
//------------------------------------------------------------------------------

/* Struct for maintaining a domain's protection keys */
typedef struct __attribute__((packed)) {
    vkey_t   vkey;            // Virtual protection key
    pkey_t   pkey;            // Arch specific protection key
    bool     owner : 1;       // Key is owned, i.e., it can be used for mmap/munmap/(pkey_)mprotect/pkey_free
    uint     perm  : 4;       // Key permissions. Bitwise OR of one or more of the following flags: PKEY_DISABLE_ACCESS, PKEY_DISABLE_WRITE
    bool     used  : 1;       // Is key slot used
    int      _reserved : 10;
} pk_key_t;
//------------------------------------------------------------------------------

/* Struct representing a domain */
typedef struct _pk_domain {
    int             used;       // Is domain slot used
    int             parent_did; // did of domain which created this domain, or DID_INVALID if none

    pk_key_t        keys[NUM_KEYS_PER_DOMAIN];
#ifndef RELEASE
    char padding1[512];
#endif
    filter_compact_t        sf_table[NUM_DOMAIN_FILTERS];
#ifndef RELEASE
    char padding2[512];
#endif
    pthread_mutex_t syscall_lock;

    int             allowed_source_domains[NUM_SOURCE_DOMAINS]; // List of domains that can call into our domain
    size_t          allowed_source_domains_count;               // Number of valid domains in allowed_source_domains
} _pk_domain;
//------------------------------------------------------------------------------

typedef struct _pk_syscall {
    trace_info_t * filter_info;      // information about the currently traced syscall passed to the filter domain (nr, args, flag, ...)
    pkru_config_t  filter_config;    // original config of filter domain (since we temporarily grant access to syscall_args_key)
    void *         filter_mem;       // isolated memory region used by filter domain, where syscall arguments are put before syscall (protected with syscall_args_key)
    arg_copy_t *   filter_arg_copy;  // how to copy args (in monitor exit handler)
    int            filteree_did;     // did of domain that gets filtered
    int            flags;
#ifndef RELEASE
    uint64_t *     filteree_stack;   // original stack pointer of filteree_did
#endif
    void *         filteree_reentry; // original reentry point of syscall
} _pk_syscall;

/* Struct for storing stack information in TLS */
typedef struct _pk_thread_domain {
    _expected_return * expected_return; // points to the stack where the struct lives in case a dcall is pending (waiting for return), or null.
    uint64_t *         user_stack_base; // base address of user stack. This field is checked to see if the struct is initialized, in which case it is not 0.
    size_t             user_stack_size; // size in bytes
    uint64_t *         user_stack;      // current position of user stack (WARNING: use GET_USER_STACK instead of accessing it directly)

    pkru_config_t      current_pkru;    // pkru config of currently running thread in current DID
    int                previous_slot;   // For RISC-V, maintains the previous key slot for round-robin key scheduling.

    _pk_syscall        syscall;
} _pk_thread_domain;
//------------------------------------------------------------------------------

/* Struct for passing function arguments / return values back to user space */
typedef struct __attribute__((packed)) {
    uint64_t valid;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
} argframe_t;
//------------------------------------------------------------------------------

// Unfortunately, libc typedef's fpregset_t as a pointer, which we cannot use
// typedef struct _libc_fpstate *fpregset_t;
// So redefine it
typedef struct _libc_fpstate fpregs_t;

/* Struct for keeping trusted data in TLS */
typedef struct __attribute__((packed)) {
#ifdef TLS_MISALIGNMENT_BUG
    char padding1[PAGESIZE];
#endif
    uint64_t * backup_user_stack;    // This must be the first dword for asm code to work. holds user stack pointer during exception handling
    uint64_t * exception_stack;      // This must be the second dword for asm code to work. top of exception stack, used for exception handling
    uint64_t * exception_stack_base; // base address of exception stack
    pkru_config_t asm_pkru;
    uint64_t filter_syscalls;        // This must be the fifth dword for asm code to work. If false, we are in the monitor (or not yet initialized). If true, syscalls/signals are filtered
    int signal_pending;              // This must be the sixth dword for asm code to work. Pending signal that needs to be handled at monitor exit
    int signal_state;                // Since int is 4-byte, this pads the sixth dword. Number of active signals
    pkru_config_t asm_pkru_backup;   // This must be the seventh dword for asm code to work. Temporary copy of asm_pkru during signal redeployment
    uint64_t syscall_backup_exception_stack; // This must be the eighth dword for asm code to work. Temporary copy of syscall stack, or NULL
    argframe_t argframe;             // This must be the nineth dword for asm code to work. Arguments/return value returned by monitor
    pk_key_t syscall_args_key;
    siginfo_t* signal_siginfo;
    ucontext_t* signal_sigframe;
    int signal_sigdid;               // Interrupted did
    int reserved;
    _pk_thread_domain thread_dom_data[NUM_DOMAINS]; // User stacks for all domains this thread visits
    sigset_t signal_mask;           // Sigmask if signal_pending != 0
    //add new fields (that are not referenced in asm below this line -----------
    stack_t sigaltstack;
    int current_did;                 // domain ID in which thread is currently executing
    int tid;                         // thread ID
    uint64_t pthread_tid;            // pthread_self
    pid_t gettid;                    // gettid
    bool init;                       // Is the thread already initialized by our library? If not, current_did and other fields are invalid, and CURRENT_DID might not be used
    bool exiting;                    // If the thread is about to pthread_exit (but might still be syscall-filtered)
    char * thread_name_debug;        // thread name for debugging

    // Fill struct up to a multiple of PAGESIZE
    #define __TLS_STRUCT_SIZE_ABOVE ( 0 \
        + sizeof(uint64_t*) * 3 \
        + sizeof(pkru_config_t) \
        + sizeof(uint64_t) \
        + sizeof(int) * 2 \
        + sizeof(pkru_config_t) \
        + sizeof(uint64_t) \
        + sizeof(argframe_t) \
        + sizeof(pk_key_t) \
        + sizeof(siginfo_t*) \
        + sizeof(ucontext_t*) \
        + sizeof(int) * 2 \
        + sizeof(_pk_thread_domain) * NUM_DOMAINS \
        + sizeof(sigset_t) \
        + sizeof(stack_t) \
        + sizeof(int) * 2 \
        + sizeof(uint64_t) \
        + sizeof(pid_t) \
        + sizeof(bool) * 2 \
        + sizeof(char*) \
    )
    unsigned char unused[PAGESIZE - __TLS_STRUCT_SIZE_ABOVE % PAGESIZE];
    #undef __TLS_STRUCT_SIZE_ABOVE
#ifdef TLS_MISALIGNMENT_BUG
    char padding2[PAGESIZE];
#endif
} _pk_tls;

/* Struct for keeping trusted data in read-only TLS */
typedef struct __attribute__((packed)) {
#ifdef TLS_MISALIGNMENT_BUG
    char padding1[PAGESIZE];
#endif
    pkru_config_t asm_pkru;          // This must be the fourth dword for asm code to work. holds current pkru config for this thread and is also needed for _pk_domain_is_key_loaded_arch

    // Fill struct up to a multiple of PAGESIZE
    #define __ROTLS_STRUCT_SIZE_ABOVE ( 0 \
        + sizeof(pkru_config_t) \
    )
    unsigned char unused[PAGESIZE - __ROTLS_STRUCT_SIZE_ABOVE % PAGESIZE];
    #undef __ROTLS_STRUCT_SIZE_ABOVE
#ifdef TLS_MISALIGNMENT_BUG
    char padding2[PAGESIZE];
#endif
} _pk_rotls;

C_STATIC_ASSERT(TTLS_OFFSET_BACKUP_USER_STACK      == offsetof(_pk_tls, backup_user_stack));
C_STATIC_ASSERT(TTLS_OFFSET_EXCEPTION_STACK        == offsetof(_pk_tls, exception_stack));
C_STATIC_ASSERT(TTLS_OFFSET_EXCEPTION_STACK_BASE   == offsetof(_pk_tls, exception_stack_base));
C_STATIC_ASSERT(TTLS_OFFSET_FILTER_SYSCALLS        == offsetof(_pk_tls, filter_syscalls));
C_STATIC_ASSERT(TTLS_OFFSET_SIGNAL_PENDING         == offsetof(_pk_tls, signal_pending));
C_STATIC_ASSERT(TTLS_OFFSET_SIGNAL_STATE           == offsetof(_pk_tls, signal_state));
C_STATIC_ASSERT(TTLS_OFFSET_BACKUP_EXCEPTION_STACK == offsetof(_pk_tls, syscall_backup_exception_stack));
C_STATIC_ASSERT(TTLS_OFFSET_ARGFRAME               == offsetof(_pk_tls, argframe));

C_STATIC_ASSERT(ROTTLS_OFFSET_CURRENT_PKRU         == offsetof(_pk_tls, asm_pkru));
C_STATIC_ASSERT(ROTTLS_OFFSET_BACKUP_PKRU          == offsetof(_pk_tls, asm_pkru_backup));
//C_STATIC_ASSERT(ROTTLS_OFFSET_CURRENT_PKRU        == offsetof(_pk_rotls, asm_pkru));
//------------------------------------------------------------------------------

C_STATIC_ASSERT((sizeof(_pk_domain) % 8) == 0);
C_STATIC_ASSERT(sizeof(pk_key_t) == 8);
C_STATIC_ASSERT((sizeof(_pk_tls) % PAGESIZE) == 0);
C_STATIC_ASSERT((sizeof(pkru_config_t) % WORDSIZE) == 0);
C_STATIC_ASSERT((sizeof(_pk_thread_domain) % 8) == 0);
C_STATIC_ASSERT((sizeof(_pk_syscall) % 8) == 0);

//------------------------------------------------------------------------------

/* Struct for book-keeping memory mappings */
typedef struct mprotect_t {
    void *       addr;  // start address
    size_t       len;   // length in bytes
    int          prot;  // page permissions, according to mmap/mprotect
    vkey_t       vkey;  // virtual protection key
    pkey_t       pkey;  // physical protection key
    bool         used;  // shows whether this mprotect_t slot is in use or not
    const char * name;
    int          mmap_flags;
    int          mmap_fd;
    off_t        mmap_offset;
} mprotect_t;
//------------------------------------------------------------------------------

/* Struct for temporarily passing pthread_create arguments from parent to child */
typedef struct {
  void* exception_stack;
  void* exception_stack_top;
  void* start_routine;
  void* arg;
  int current_did;
} pthread_arg_t;
//------------------------------------------------------------------------------
typedef struct {
  char * path;
  int    domain;
} path_domain;
//------------------------------------------------------------------------------

/* Global struct for all essential data */
typedef struct _pk_data {
    int             initialized;
    int             tracer_started;                     // indicates that a sysfilter tracer was started (do not allow to start a second one)
    pthread_mutex_t mutex;                              // Global PK mutex
    pthread_mutex_t condmutex;                          // Mutex for cond
    pthread_cond_t  cond;                               // Condition variable for syncing pthread creation
    size_t          stacksize;                          // Size of user stacks we lazily allocating pthread stacks
    pthread_arg_t   pthread_arg;                        // For passing pthread_create arguments from parent to child thread
    void            (*user_exception_handler)(void*);   // Forward pk exceptions to a user program (currently only for debugging)

    _pk_domain      domains[NUM_DOMAINS];               // List of all domains

    _pk_tls *       threads[NUM_THREADS];               // Pointers to TLS to manage threads which are currently not running
    mprotect_t      ranges[NUM_MPROTECT_RANGES];        // List of memory mappings
    size_t          ranges_max_used;
    size_t          stat_num_exceptions;                // Statistics for number of exceptions

    path_domain     private_files[NUM_PRIVATE_FILES];
    int             binary_scanning; //flag to enable/disable binary scanning and W^X etc

} _pk_data;
//------------------------------------------------------------------------------

/* Struct for registered ecalls */
typedef struct _pk_ecall {
    char * name;    // for debugging
    void * entry;   // Ecall entry point
    int did;        // Ecall registered for this domain
} _pk_ecall;
//------------------------------------------------------------------------------

// Kernel interface uses different sigaction struct than glibc, which is, 
// unfortunately, not exported. See kernel_sigaction.h
struct kernel_sigaction
{
  sighandler_t k_sa_handler;
  unsigned long sa_flags;
  void (*sa_restorer) (void);
  /* glibc sigset is larger than kernel expected one, however sigaction
     passes the kernel expected size on rt_sigaction syscall.  */
  sigset_t sa_mask;
};


//------------------------------------------------------------------------------
// Variable declarations
//------------------------------------------------------------------------------
extern _pk_data pk_data;                      // Global pk data
extern __thread _pk_tls  pk_trusted_tls;      // Per-thread pk data
//extern __thread _pk_rotls  pk_trusted_rotls;  // Per-thread pk data
#define pk_trusted_rotls pk_trusted_tls

extern uint64_t _pk_ttls_offset;              // Offset of pk_trusted_tls from thread pointer (fs on x86, or tp on RISC-V)
extern pk_key_t rokey_for_exception_handler;


#ifdef DL_HOOKING

extern void *(*real_mmap)(void *, size_t, int, int, int, off_t);
extern int   (*real_munmap)(void *addr, size_t length);
extern int   (*real_madvise)(void *addr, size_t length, int advice);
extern void *(*real_mremap)(void *old_address, size_t old_size,
                    size_t new_size, int flags, void *new_address);
extern int   (*real_mprotect)(void *, size_t, int);
extern int   (*real_pkey_alloc)(unsigned int flags, unsigned int access_rights);
extern int   (*real_pkey_free)(int pkey);
extern int   (*real_pkey_mprotect)(void *addr, size_t len, int prot, int pkey);
extern int   (*real_pthread_create)(pthread_t *thread, const pthread_attr_t *attr,
                             void *(*start_routine) (void *), void *arg);

#define MMAP             real_mmap
#define MUNMAP           real_munmap
#define MADVISE          real_madvise
#define MREMAP           real_mremap
#define MPROTECT         real_mprotect
#define PKEY_ALLOC       pkey_alloc
#define PKEY_FREE        pkey_free
#define PKEY_MPROTECT    pkey_mprotect
#define SIGACTION        real_sigaction
#define SIGNAL           real_signal
#define PTHREAD_CREATE   real_pthread_create
#define PTHREAD_EXIT     real_pthread_exit

#else // DL_HOOKING

#define MMAP             mmap
#define MUNMAP           munmap
#define MADVISE          madvise
#define MREMAP           mremap
#define MPROTECT         mprotect
#define PKEY_ALLOC       pkey_alloc
#define PKEY_FREE        pkey_free
#define PKEY_MPROTECT    pkey_mprotect
#define SIGACTION        sigaction
#define SIGNAL           signal
#define PTHREAD_CREATE   pthread_create
#define PTHREAD_EXIT     pthread_exit

#endif // DL_HOOKING

//------------------------------------------------------------------------------
// Internal API functions
//------------------------------------------------------------------------------
void     PK_CODE _pk_my_debug_check();
int      PK_CODE _pk_init(int flags, void* arg1, void* arg2);
int      PK_CODE _pk_deinit(void);
int      PK_CODE _pk_domain_create(unsigned int flags);
int      PK_CODE _pk_domain_free(int did);
int      PK_CODE _pk_domain_release_child(int did);
vkey_t   PK_CODE _pk_pkey_alloc(unsigned int flags, unsigned int access_rights);
vkey_t   PK_CODE _pk_pkey_alloc2(int did, unsigned int flags, unsigned int access_rights);
int      PK_CODE _pk_pkey_free(vkey_t vkey);
int      PK_CODE _pk_pkey_free2(int did, vkey_t vkey);
int      PK_CODE _pk_domain_assign_pkey(int did, vkey_t vkey, int flags, unsigned int access_rights);
int      PK_CODE _pk_domain_default_key(int did);
int      PK_CODE _pk_pkey_mprotect(void *addr, size_t len, int prot, vkey_t vkey);
int      PK_CODE _pk_pkey_mprotect2(int did, void *addr, size_t len, int prot, vkey_t vkey);
void*    PK_CODE _pk_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void*    PK_CODE _pk_mmap2(int did, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void*    PK_CODE _pk_mmap3(vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int      PK_CODE _pk_munmap(void* addr, size_t len);
int      PK_CODE _pk_munmap2(int did, void* addr, size_t len);
int      PK_CODE _pk_madvise(void* addr, size_t len, int advice);
int      PK_CODE _pk_madvise2(int did, void* addr, size_t len, int advice);
void*    PK_CODE _pk_mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address);
void*    PK_CODE _pk_mremap2(int did, void *old_address, size_t old_size, size_t new_size, int flags, void *new_address);
int      PK_CODE _pk_mprotect(void *addr, size_t len, int prot);
int      PK_CODE _pk_mprotect2(int did, void *addr, size_t len, int prot);
void     PK_CODE _pk_name_range(void *addr, size_t len, const char * name);
int      PK_CODE _pk_domain_register_ecall(int ecall_id, void* entry);
int      PK_CODE _pk_domain_register_ecall2(int did, int ecall_id, void* entry);
int      PK_CODE _pk_domain_register_ecall3(int did, int ecall_id, void* entry, char * name);
int      PK_CODE _pk_domain_allow_caller(int caller_did, unsigned int flags);
int      PK_CODE _pk_domain_allow_caller2(int did, int caller_did, unsigned int flags);
int      PK_CODE _pk_domain_load_key(vkey_t vkey, int slot, unsigned int flags);
int      PK_CODE _pk_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                                    void *(*start_routine) (void *), void *arg);
void     PK_CODE _pk_pthread_exit(void* retval);
void     PK_CODE _pk_pthread_exit_c(void* retval);
int      PK_CODE _pk_register_exception_handler(void (*handler)(void*));
int      PK_CODE _pk_sysfilter_domain(int did, int sys_nr, filter_t filter, arg_copy_t arg_copy[]);
int      PK_CODE _pk_sysfilter_module_intercept(int sysno);
int      PK_CODE _pk_sysfilter_monitor(int sys_nr, filter_t filter, arg_copy_t arg_copy[]);
struct sf_tracee_function;
int      PK_CODE _pk_sysfilter_tracer(tracer_t tracer, pid_t tracee);
bool     PK_CODE _pk_domain_can_access_memory_syscall(int did, const void * addr, size_t len, bool write);
int      PK_CODE _pk_domain_can_access_string_syscall(int did, const void * addr, bool write_access);
int      PK_CODE _pk_api_generic(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int      PK_CODE _pk_set_binary_scanning(uint64_t arg1);

int      PK_CODE _pk_sigaction(int signum, const struct sigaction *act,
                               struct sigaction *oldact);
int      PK_CODE _pk_sigaction2(int did, int signum, const struct sigaction *act,
                                struct sigaction *oldact);
__sighandler_t PK_CODE _pk_signal(int signum, sighandler_t handler);
__sighandler_t PK_CODE _pk_signal2(int did, int signum, sighandler_t handler);
int      PK_CODE _pk_sigaction_krnl2(int did, int signum, const struct kernel_sigaction *kact,
                                     struct kernel_sigaction *koldact);

//------------------------------------------------------------------------------
// Internal functions
//------------------------------------------------------------------------------
int      PK_CODE _pk_exception_key_mismatch_unlocked(void * bad_addr);
uint64_t PK_CODE _pk_exception_handler_unlocked(uint64_t data, uint64_t id, uint64_t type, uint64_t * stack_of_caller, void * reentry);
void*    PK_CODE _pk_mmap_internal(int did, vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void*    PK_CODE _pk_mremap_internal(int did, void *old_address, size_t old_size, size_t new_size, int flags, void *new_address);
int      PK_CODE _pk_pkey_mprotect_unlocked(int did, void *addr, size_t len, int prot, vkey_t vkey, int mmap_flags, int mmap_fd, off_t mmap_offset);
int      PK_CODE _pk_pkey_mprotect_unlocked_nodid_check(int did, void *addr, size_t len, int prot, vkey_t vkey, int mmap_flags, int mmap_fd, off_t mmap_offset);
int      PK_CODE _pk_pkey_munprotect_unlocked(int did, void *addr, size_t len, int prot);
vkey_t   PK_CODE _pk_pkey_alloc_unlocked(int did, unsigned int flags, unsigned int access_rights);
int      PK_CODE _pk_domain_register_ecall3_unlocked(int did, int ecall_id, void* entry, char* name);
int      PK_CODE _pk_domain_allow_caller2_unlocked(int did, int caller_did, unsigned int flags);
int      PK_CODE _pk_current_did(void);
int      PK_CODE _pk_simple_api_call(int a, int b, int c, int d, int e, int f);
//char *   PK_CODE _pk_sprint_sysent(sysent_t * sysent, int sysno);
void     PK_CODE _pk_print_sysfilters(sysent_t * sf_table, int num);
char *   PK_CODE _pk_domain_str(int did);
char *   PK_CODE _pk_print_keys(int did);
char *   PK_CODE _pk_get_domain_name(int did);
void     PK_CODE _pk_print_debug_info();
void     PK_CODE _pk_print_debug_info2(void* addr, size_t len);
void     PK_CODE _pthread_init_function_c(void * start_routine, void * current_user_stack);
int      PK_CODE _pk_domain_load_key_unlocked(int did, vkey_t vkey, int slot, unsigned int flags);
int      PK_CODE _pk_domain_load_pkkey_unlocked(int did, pk_key_t * key, int slot);

int      PK_CODE _pk_domain_create_unlocked(unsigned int flags);
int      PK_CODE _pk_domain_assign_pkey_unlocked(int source_did, int target_did, vkey_t vkey, int flags, unsigned int access_rights, bool load_key);
void*    PK_CODE _pk_setup_thread_exception_stack(void);
int      PK_CODE _pk_init_thread(int did, void* exception_stack);
//void     PK_CODE_INLINE _pk_setup_default_config_for_current_thread(int did);

int      PK_CODE _pk_selfprotect(int did, vkey_t vkey);
int      PK_CODE _pk_selfunprotect();
char *   PK_CODE _pk_get_domain_name(int did);
//_pk_thread_domain * PK_CODE _pk_get_thread_domain_data_nodidcheck(int did);
int PK_CODE _allocate_user_stack(int did, _pk_thread_domain * data);
int PK_CODE _deallocate_user_stack(_pk_thread_domain * data);
void PK_CODE _allocate_filter_mem(int did, pk_key_t * sysargs_key, _pk_thread_domain *data);
int PK_CODE _deallocate_filter_mem(_pk_thread_domain *data);

bool PK_CODE _track_memory(void *addr, size_t len, int prot, vkey_t vkey, pkey_t pkey, bool is_mmap, int mmap_flags, int mmap_fd, off_t mmap_offset);
bool PK_CODE _untrack_memory(void *addr, size_t len);
void * PK_CODE _allocate_stack(size_t stack_size);
int PK_CODE _pk_scan_memory_incl_pitfalls(void *addr, size_t len);
void PK_CODE _register_fd_for_monitor(int fd);
void PK_CODE _unregister_fd_for_monitor(int fd);
int PK_CODE _pk_set_binary_scanning_unlocked(uint64_t arg1);

//------------------------------------------------------------------------------
// Inline functions
//------------------------------------------------------------------------------

FORCE_INLINE int _pk_init_lock() {
  int ret;
  pthread_mutexattr_t attr;
  if (0 != pthread_mutexattr_init(&attr) ||
      0 != pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) {
    ERROR("Unable to initialize mutex attributes");
    errno = EINVAL;
    return -1;
  }
  ret = pthread_mutex_init(&pk_data.mutex, &attr);
  if (ret) {
    ERROR("Unable to initialize mutex");
    errno = EINVAL;
    return -1;
  }
  assert(0 == pthread_mutexattr_destroy(&attr));

  ret = pthread_mutex_init(&pk_data.condmutex, NULL);
  if (ret) {
    ERROR("Unable to initialize cond-mutex");
    errno = EINVAL;
    return -1;
  }

  ret = pthread_cond_init(&pk_data.cond, NULL);
  if (ret) {
    ERROR("Unable to initialize condition variable");
    errno = EINVAL;
    return -1;
  }

  return 0;
}
//------------------------------------------------------------------------------
//PK_CODE_INLINE
bool FORCE_INLINE _domain_exists(int did){
    return (did >= 0 && did < NUM_DOMAINS && pk_data.domains[did].used);
}

//------------------------------------------------------------------------------

FORCE_INLINE bool _domain_is_descendant(int did){
    if (!_domain_exists(did)) {
      return false;
    }

    int parent = did;
    do {
        parent = pk_data.domains[parent].parent_did;
        if (DID_INVALID == parent) {
            return false;
        }
    } while (parent != CURRENT_DID);
    return true;
}
//------------------------------------------------------------------------------

//PK_CODE_INLINE
FORCE_INLINE _pk_tls * _get_thread_data(void) {
    assert_ifdebug(pk_trusted_tls.init);
    assert_ifdebug(pk_trusted_tls.current_did != DID_INVALID);
    assert_ifdebug(pk_trusted_tls.exception_stack_base != 0);
    assert_ifdebug(pk_trusted_tls.exception_stack != 0);
    assert_ifdebug(pk_trusted_tls.tid >= 0 && pk_trusted_tls.tid < NUM_THREADS);
    if (pk_data.threads[pk_trusted_tls.tid] != THREAD_UNUSED && pk_data.threads[pk_trusted_tls.tid] != THREAD_EXITING) {
        assert_ifdebug(pk_data.threads[pk_trusted_tls.tid]->tid == pk_trusted_tls.tid);
    }

    return &pk_trusted_tls;
}

//------------------------------------------------------------------------------
vkey_t PK_CODE_INLINE _get_default_vkey(int did){
    if (!_domain_exists(did)) {
        ERROR("Invalid did");
        return VKEY_INVALID;
    }

    // first slot holds default key
    if (!pk_data.domains[did].keys[0].used) {
        ERROR("Default key[0] is unused");
        return VKEY_INVALID;
    }

    if (!pk_data.domains[did].keys[0].owner) {
        ERROR("Default key[0] has no owner permission");
        return VKEY_INVALID;
    }

    assert_ifdebug(pk_data.domains[did].keys[0].pkey != 0);
    return pk_data.domains[did].keys[0].vkey;
}
//------------------------------------------------------------------------------

pkey_t PK_CODE_INLINE _vkey_to_pkey(int did, vkey_t vkey){
    //DEBUG_MPK("_vkey_to_pkey(%d, %d)", did, vkey);
    if (!_domain_exists(did) || VKEY_INVALID == vkey) {
      return PKEY_INVALID;
    }

    for (size_t key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++){
        if (pk_data.domains[did].keys[key_id].used &&
            pk_data.domains[did].keys[key_id].vkey == vkey) {
                return pk_data.domains[did].keys[key_id].pkey;
        }
    }
    assert(false);
}
//------------------------------------------------------------------------------

FORCE_INLINE void _pk_setup_default_config_for_thread(int did, _pk_tls *tls) {
    //assert_ifdebug(pk_trusted_tls.thread_dom_data[did].user_stack_base != 0);
    tls->thread_dom_data[did].current_pkru = _pk_create_default_config_arch(did);
}

//------------------------------------------------------------------------------
FORCE_INLINE _pk_thread_domain * _pk_get_thread_domain_data_tls_nodidcheck(int did, _pk_tls *tls) {
    assert_ifdebug(_domain_exists(did));
    int ret;

    //get data
    _pk_thread_domain * data = &(tls->thread_dom_data[did]);
    assert_ifdebug( (uintptr_t)data % WORDSIZE == 0); //check that pointer to member within a packed struct is aligned.

    // initialize lazily/on demand
    if(likely(data->user_stack_base != 0 && data->syscall.filter_mem != 0)){
        assert_ifdebug(data->user_stack_size != 0);
        return data;
    }

    if (data->user_stack_base == 0) {
        DEBUG_MPK("data->user_stack_base == 0");
        ret = _allocate_user_stack(did, data);
        if(ret != 0){
            //errno set by _allocate_user_stack
            ERROR_FAIL("_allocate_user_stack failed");
        }

        DEBUG_MPK("generating PKRU default_config for this thread. did=%d.", did);
        _pk_setup_default_config_for_thread(did, tls);
    }

    if (data->syscall.filter_mem == 0) {
        DEBUG_MPK("data->syscall.args == 0");
        _allocate_filter_mem(did, &tls->syscall_args_key, data);
    }
    return data;
}
//--------------------------------------------------------------------------------

FORCE_INLINE _pk_thread_domain * _pk_get_thread_domain_data_nodidcheck(int did) {
    return _pk_get_thread_domain_data_tls_nodidcheck(did, _get_thread_data());
}
//------------------------------------------------------------------------------

FORCE_INLINE bool _user_stack_push_allowed(_pk_thread_domain * data, uintptr_t stack_pointer, size_t size) {

    assert_ifdebug(data->user_stack_size);
    assert_ifdebug(data->user_stack_base);
    assert_ifdebug(size < data->user_stack_size);

    if(unlikely(
        stack_pointer - size <  (uintptr_t)data->user_stack_base ||
        stack_pointer        >= (uintptr_t)data->user_stack_base + data->user_stack_size
    )){
        WARNING("Push not allowed: stack frame= (0x%lx, 0x%lx), stack = (%p,0x%lx)", 
            stack_pointer, size, data->user_stack_base, data->user_stack_size);
        return false;
    }
    return true;
}
//------------------------------------------------------------------------------

FORCE_INLINE bool _thread_domain_initialized(int did) {
    assert_ifdebug(did >= 0 && did < NUM_DOMAINS);
    return pk_trusted_tls.thread_dom_data[did].user_stack_base != 0;
}
//------------------------------------------------------------------------------

FORCE_INLINE pkru_config_t _pk_setup_domain_pkru(int did) {
    pkru_config_t default_config = _pk_create_default_config_arch(did);
    pk_trusted_tls.thread_dom_data[did].current_pkru = default_config;
    return default_config;
}
//------------------------------------------------------------------------------

FORCE_INLINE pkru_config_t read_pkru_current_thread(int target_did) {
    #ifdef __riscv
        if(target_did == CURRENT_DID){
            return _read_pkru_reg();
        }
    #endif

    assert_ifdebug( _thread_domain_initialized(target_did));
    pkru_config_t config = pk_trusted_tls.thread_dom_data[target_did].current_pkru;

    #ifdef __riscv
        assert_ifdebug(!_thread_domain_initialized(target_did) || (_thread_domain_initialized(target_did) && config.mode == 1)); //otherwise it's not initialized yet and we should probably call _pk_create_default_config_arch(did)
        assert_ifdebug(!_thread_domain_initialized(target_did) || (_thread_domain_initialized(target_did) && config.sw_did == target_did)); //sanity check
    #endif

    return config;
}
//------------------------------------------------------------------------------

FORCE_INLINE void write_pkru_current_thread(int target_did, pkru_config_t config) {
    DEBUG_MPK("write_pkru_current_thread did = %d (current did = %d), config = %s", target_did, CURRENT_DID, pk_sprint_reg_arch(config));

    //sanity checks
    assert_ifdebug( _thread_domain_initialized(target_did));
    #ifdef __riscv
        assert_ifdebug(config.sw_did == target_did);
        assert_ifdebug(config.mode == 1);
    #endif


    pk_trusted_tls.thread_dom_data[target_did].current_pkru = config;
    if(target_did == CURRENT_DID){
        #ifdef __riscv
            DEBUG_MPK("writing pkru to register");
            _write_pkru_reg(config);
        #else
            pk_trusted_rotls.asm_pkru = config;
        #endif
    }
}
//------------------------------------------------------------------------------

FORCE_INLINE pkru_config_t read_pkru(int target_did, size_t tid) {
    assert_ifdebug(tid < NUM_THREADS);
    assert_ifdebug(target_did >= 0 && target_did < NUM_DOMAINS);
    assert_ifdebug(pk_data.threads[tid]->thread_dom_data[target_did].user_stack_base != 0);

    return pk_data.threads[tid]->thread_dom_data[target_did].current_pkru;
}
//------------------------------------------------------------------------------

/*
FORCE_INLINE void write_pkru(int target_did, pkru_config_t config, size_t tid) {
    assert(0); // we should never have to write pkru of another thread
}
*/
//------------------------------------------------------------------------------

FORCE_INLINE void _pk_domain_switch(int type, int target_did, void* entry_point, uint64_t* target_stack) {
    pkru_config_t config = read_pkru_current_thread(target_did);
    pk_trusted_tls.argframe.valid = 0;
    _pk_domain_switch_arch(type, target_did, config, entry_point, target_stack);
    // update current_pkru in TLS to reflect pkru modifications
    write_pkru_current_thread(target_did, config);
    //pk_trusted_tls.asm_pkru = config;
}
//------------------------------------------------------------------------------

// Push arguments onto the user stack
// This function must be called after _pk_domain_switch
FORCE_INLINE void _pk_domain_switch_push_argument(uint64_t argument) {
    pk_trusted_tls.backup_user_stack--;
    *pk_trusted_tls.backup_user_stack = argument;
}
//------------------------------------------------------------------------------

FORCE_INLINE void _pk_domain_switch_prepare_call(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    // function must be called after _pk_domain_switch
    assert_ifdebug(pk_trusted_tls.argframe.valid == 0);
    pk_trusted_tls.argframe.valid = 1;
    pk_trusted_tls.argframe.arg0 = arg0;
    pk_trusted_tls.argframe.arg1 = arg1;
    pk_trusted_tls.argframe.arg2 = arg2;
    pk_trusted_tls.argframe.arg3 = arg3;
    pk_trusted_tls.argframe.arg4 = arg4;
    pk_trusted_tls.argframe.arg5 = arg5;
}
//------------------------------------------------------------------------------

void diehere();
#include <errno.h>
#ifndef PROXYKERNEL
#define _pk_acquire_lock() do{ \
    DEBUG_LOCK(" _pk_acquire_lock start %p. %s:%d", (void*)pthread_self(), __FILE__, __LINE__); \
    assert(0 == pthread_mutex_lock(&pk_data.mutex)); \
    DEBUG_LOCK(" _pk_acquire_lock end %p. %s:%d", (void*)pthread_self(), __FILE__, __LINE__); \
} while(0)  
//------------------------------------------------------------------------------
#define _pk_acquire_lock1() do{ \
    DEBUG_LOCK(" _pk_acquire_lock start %p. %s:%d", (void*)pthread_self(), __FILE__, __LINE__); \
    /*assert(0 == pthread_mutex_lock(&pk_data.mutex));*/ \
    int _ret = pthread_mutex_trylock(&pk_data.mutex); \
    if (_ret != 0) { \
        printf("_pk_acquire_lock failed: %s\n", strerror(_ret)); \
        diehere(); \
    } \
    DEBUG_LOCK(" _pk_acquire_lock end %p. %s:%d", (void*)pthread_self(), __FILE__, __LINE__); \
} while(0)
//------------------------------------------------------------------------------
#define _pk_release_lock() do{ \
    DEBUG_LOCK(" _pk_release_lock start %p. %s:%d", (void*)pthread_self(), __FILE__, __LINE__); \
    int _ret = pthread_mutex_unlock(&pk_data.mutex); \
    DEBUG_LOCK("res: %d: %s", _ret, strerror(_ret)); \
    assert(0 == _ret); \
    DEBUG_LOCK(" _pk_release_lock end %p. %s:%d", (void*)pthread_self(), __FILE__, __LINE__); \
} while(0)
//------------------------------------------------------------------------------
#else
#define _pk_acquire_lock() do{} while(0)
#define _pk_release_lock() do{} while(0)
#endif /* PROXYKERNEL */
//FORCE_INLINE void _pk_acquire_lock() {
//#ifndef PROXYKERNEL
//  DEBUG_MPK("start %p", (void*)pthread_self());
//  assert(0 == pthread_mutex_lock(&pk_data.mutex));
//  DEBUG_MPK("end");
//#endif /* PROXYKERNEL */
//}
//FORCE_INLINE void _pk_release_lock() {
//#ifndef PROXYKERNEL
//  DEBUG_MPK("start %p", (void*)pthread_self());
//  int ret = pthread_mutex_unlock(&pk_data.mutex);
//  DEBUG_MPK("res: %d: %s", ret, strerror(ret));
//  assert(0 == ret);
//  DEBUG_MPK("end");
//#endif /* PROXYKERNEL */
//}
//------------------------------------------------------------------------------

FORCE_INLINE const char * type_str(int type)
{
    if(type >= 5 || type < 0){
        type = 5;
    }
    static const char * pk_type_str[] = {"RET", "CALL", "API", "SYSCALL_RET", "EXCEPTION", "__???????__"};
    return pk_type_str[type];
}
//------------------------------------------------------------------------------

FORCE_INLINE bool _memory_overlaps(void* addr1, size_t len1, void* addr2, size_t len2) {
    return ((uintptr_t)addr1 < (uintptr_t)addr2 + len2) &&
          ((uintptr_t)addr1 + len1 > (uintptr_t)addr2);
}
//------------------------------------------------------------------------------

FORCE_INLINE bool _memory_fully_contained(void* addr1, size_t len1, void* addr2, size_t len2) {
    return ((uintptr_t)addr1 >= (uintptr_t)addr2) &&
          ((uintptr_t)addr1 + len1) <= ((uintptr_t)addr2 + len2);
}
//------------------------------------------------------------------------------

FORCE_INLINE bool _domain_has_vkey_nodidcheck(int did, vkey_t vkey){
    assert_ifdebug(_domain_exists(did));

    for (size_t key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++){
        if (pk_data.domains[did].keys[key_id].used &&
            pk_data.domains[did].keys[key_id].vkey == vkey) {
            return true;
        }
    }
    return false;
}
//------------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

#endif // __ASSEMBLY__
