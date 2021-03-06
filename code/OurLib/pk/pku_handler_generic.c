#define _GNU_SOURCE 1

#include <signal.h>
#include <errno.h>

#include "pk.h"
#include "pk_internal.h"

//------------------------------------------------------------------------------
// Internal globals
//------------------------------------------------------------------------------

pthread_mutex_t pku_mutex;

unsigned char pk_initialized = 0;
PK_API int domain_of_main = DID_FOR_ROOT_DOMAIN;

int _pku_dl_hooking(void);

extern int pk_do_init(int flags, void* arg1, void* arg2);

#ifdef DLU_HOOKING
// Intercept libc/pthread functions and forward them to pk
// For this to work, libpku.so needs to be preloaded

// If pk is not initialized, we fall back to the original libc/pthread
// functions real_xxx inside GEN_CALL_WRAPPER_API_FALLBACK

#include <dlfcn.h>

int          (*real_sigaction)(int signum, const struct sigaction *act,
                               struct sigaction *oldact) = NULL;
sighandler_t (*real_signal)(int signum, sighandler_t handler) = NULL;
void        *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
int          (*real_munmap)(void *addr, size_t length) = NULL;
int          (*real_madvise)(void *addr, size_t length, int advice) = NULL;
int          (*real_mprotect)(void *, size_t, int) = NULL;
int          (*real_pkey_alloc)(unsigned int flags, unsigned int access_rights) = NULL;
int          (*real_pkey_free)(int pkey) = NULL;
int          (*real_pkey_mprotect)(void *addr, size_t len, int prot, int pkey) = NULL;
int          (*real_pthread_create)(pthread_t *thread, const pthread_attr_t *attr,
                                    void *(*start_routine) (void *), void *arg) = NULL;
int          (*real_pthread_exit)(void *retval) = NULL;

#endif // DLU_HOOKING

// Initialize the mutex in first constructor. This always needs to be
// done in constructor, no matter if CONSTRUCTOR is defined or not
__attribute__((constructor(101)))
void _pku_ctor_mutex(){
    DEBUG_MPK("_pku_ctor_mutex");
    assert(0 == pthread_mutex_init(&pku_mutex, NULL));
}

#ifdef CONSTRUCTOR

__attribute__((constructor(102)))
void _pku_ctor(){
    DEBUG_MPK("_pku_ctor");

#ifdef DLU_HOOKING
    if (-1 == _pku_dl_hooking()) {
        ERROR("pk_init: failed to hook libc");
        // errno set by _pku_dl_hooking
    }
#endif // DLU_HOOKING

    //~ This is done in sf_self_init_ctor now
    //~ if(pk_init(0, NULL, NULL) != 0){
        //~ ERROR_FAIL("PKU constructor: pk_init failed");
    //~ }
}
//------------------------------------------------------------------------------

__attribute__((destructor(101)))
void _pku_dtor(){
    DEBUG_MPK("_pku_dtor");
    if(pk_deinit() != 0){
        DEBUG_MPK("PKU destructor: pk_deinit failed");
    }
}
//------------------------------------------------------------------------------
#endif /* CONSTRUCTOR */

void PK_API pk_print_current_reg() {
    pk_print_reg_arch(_read_pkru_reg());
}
//------------------------------------------------------------------------------

void PK_API pk_debug_usercheck(int expected_did) {
    assert(pk_current_did() == expected_did);
    pk_debug_usercheck_arch();
}
//------------------------------------------------------------------------------

#define SIGMAX 256
struct sigaction registered_signals[SIGMAX] = {0,};

// This wrapper is invoked by _pk_sa_sigaction_asm, which sets up
// the stack
void* _pk_sa_sigaction_c(int sig, siginfo_t *info, void *ucontext) {
  DEBUG_MPK("_pk_sa_sigaction intercepting signal %d '%s'", sig, strsignal(sig));
  // By doing *any* PK-API call, the trusted handler will restore the
  // correct pkru settings for us
  //~ pk_simple_api_call(0,0,0,0,0,0);
  //psiginfo(info, "_pk_sa_sigaction_c");
  // pkru should be restored. From now on, we are allowed to call the
  // signal handler registered by the user
  assert(sig >= 0 && sig < SIGMAX);
  assert(registered_signals[sig].sa_handler);
  // We do not call handler directly in C, since we need to restore the
  // original user stack
  if (registered_signals[sig].sa_flags & SA_SIGINFO) {
    //DEBUG_MPK("sigaction: %p", registered_signals[sig].sa_sigaction);
    return (void*)registered_signals[sig].sa_sigaction;
  } else {
    //DEBUG_MPK("handler: %p", registered_signals[sig].sa_handler);
    return (void*)registered_signals[sig].sa_handler;
  }
}
//------------------------------------------------------------------------------

#ifdef DLU_HOOKING
#include <dlfcn.h>

int PK_API sigaction(int signum, const struct sigaction *act,
                     struct sigaction *oldact) {
  DEBUG_MPK("Intercept sigaction");
#ifdef UNSAFE_SIGNALS
  return real_sigaction(signum, act, oldact);
#else
  return pk_sigaction(signum, act, oldact);
#endif
}
//------------------------------------------------------------------------------

sighandler_t PK_API signal(int signum, sighandler_t handler) {
  DEBUG_MPK("Intercept signal");
#ifdef UNSAFE_SIGNALS
  return real_signal(signum, handler);
#else
  return pk_signal(signum, handler);
#endif
}
//------------------------------------------------------------------------------

void PK_API *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  DEBUG_MPK("Intercept mmap");
  // load real symbol for FALLBACK
  if (!real_mmap) {
    DEBUG_MPK("Hooking mmap\n");
    real_mmap = dlsym(RTLD_NEXT, "mmap");
  }
  return pk_mmap(addr, length, prot, flags, fd, offset);
}
//------------------------------------------------------------------------------

int PK_API munmap(void *addr, size_t length) {
  DEBUG_MPK("Intercept munmap");
  // load real symbol for FALLBACK
  if (!real_munmap) {
    DEBUG_MPK("Hooking munmap\n");
    real_munmap = dlsym(RTLD_NEXT, "munmap");
  }
  return pk_munmap(addr, length);
}
//------------------------------------------------------------------------------

int PK_API madvise(void *addr, size_t length, int advice) {
  DEBUG_MPK("Intercept madvise");
  // load real symbol for FALLBACK
  if (!real_madvise) {
    DEBUG_MPK("Hooking madvise\n");
    real_madvise = dlsym(RTLD_NEXT, "madvise");
  }
  return pk_madvise(addr, length, advice);
}
//------------------------------------------------------------------------------

int PK_API mprotect(void *addr, size_t len, int prot) {
  DEBUG_MPK("Intercept mprotect");
  // load real symbol for FALLBACK
  if (!real_mprotect) {
    DEBUG_MPK("Hooking mprotect\n");
    real_mprotect = dlsym(RTLD_NEXT, "mprotect");
  }
  return pk_mprotect(addr, len, prot);
}
//------------------------------------------------------------------------------

// They are simulated in mprotect.c
//~ int PK_API pkey_alloc(unsigned int flags, unsigned int access_rights) {
  //~ DEBUG_MPK("Intercept real_pkey_alloc");
  //~ return pk_pkey_alloc(flags, access_rights);
//~ }
//~ //------------------------------------------------------------------------------

//~ int PK_API pkey_free(int pkey) {
  //~ DEBUG_MPK("Intercept pkey_free");
  //~ return pk_pkey_free(pkey);
//~ }
//~ //------------------------------------------------------------------------------

//~ int PK_API pkey_mprotect(void *addr, size_t len, int prot, int pkey) {
  //~ DEBUG_MPK("Intercept pkey_mprotect");
  //~ return pk_pkey_mprotect(addr, len, prot, pkey);
//~ }
//------------------------------------------------------------------------------

int PK_API pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg) {
  DEBUG_MPK("Intercept pthread_create");
  // load real symbol for FALLBACK
  if (!real_pthread_create) {
    DEBUG_MPK("Hooking pthread_create\n");
    real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
  }
  return pk_pthread_create(thread, attr, start_routine, arg);
}
//------------------------------------------------------------------------------

 __attribute__ ((__noreturn__))
void PK_API pthread_exit(void *retval) {
  DEBUG_MPK("Intercept pthread_exit");
  // load real symbol for FALLBACK
  if (!real_pthread_exit) {
    DEBUG_MPK("Hooking real_pthread_exit\n");
    real_pthread_exit = dlsym(RTLD_NEXT, "pthread_exit");
  }
  pk_pthread_exit(retval);
}
//------------------------------------------------------------------------------

int _pku_dl_hooking(void) {
  if (!real_sigaction) {
    DEBUG_MPK("Hooking sigaction");
    real_sigaction = dlsym(RTLD_NEXT, "sigaction");
  }
  if (!real_signal) {
    DEBUG_MPK("Hooking signal");
    real_signal = dlsym(RTLD_NEXT, "signal");
  }
  if (!real_mmap) {
    DEBUG_MPK("Hooking mmap\n");
    real_mmap = dlsym(RTLD_NEXT, "mmap");
  }
  if (!real_munmap) {
    DEBUG_MPK("Hooking munmap\n");
    real_munmap = dlsym(RTLD_NEXT, "munmap");
  }
  if (!real_madvise) {
    DEBUG_MPK("Hooking madvise\n");
    real_madvise = dlsym(RTLD_NEXT, "madvise");
  }
  if (!real_mprotect) {
    DEBUG_MPK("Hooking mprotect\n");
    real_mprotect = dlsym(RTLD_NEXT, "mprotect");
  }
  if (!real_pkey_alloc) {
    DEBUG_MPK("Hooking pkey_alloc\n");
    real_pkey_alloc = dlsym(RTLD_NEXT, "pkey_alloc");
  }
  if (!real_pkey_free) {
    DEBUG_MPK("Hooking pkey_free\n");
    real_pkey_free = dlsym(RTLD_NEXT, "pkey_free");
  }
  if (!real_pkey_mprotect) {
    DEBUG_MPK("Hooking pkey_mprotect\n");
    real_pkey_mprotect = dlsym(RTLD_NEXT, "pkey_mprotect");
  }
  if (!real_pthread_create) {
    DEBUG_MPK("Hooking pthread_create\n");
    real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
  }
  if (!real_pthread_exit) {
    DEBUG_MPK("Hooking real_pthread_exit\n");
    real_pthread_exit = dlsym(RTLD_NEXT, "pthread_exit");
  }
  if (
      !real_sigaction ||
      !real_signal ||
      !real_mmap ||
      !real_munmap ||
      !real_madvise ||
      !real_mprotect ||
      !real_pkey_alloc ||
      !real_pkey_free ||
      !real_pkey_mprotect ||
      !real_pthread_create ||
      !real_pthread_exit
      ) {
    errno = EACCES;
    return -1;
  }
  return 0;
}

#endif // DLU_HOOKING

int PK_API pk_init(int flags, void* arg1, void* arg2) {
  int child = -1;
  int pk_do_init_finished = 0;
  assert(0 == pthread_mutex_lock(&pku_mutex));

  if (pk_initialized) {
    WARNING("pk already initialized");
    child = 0;
    goto cleanup;
  }

  child = pk_do_init(flags, arg1, arg2);
  if (-1 == child) {
    // errno set by pk_do_init
    goto error;
  }
  pk_do_init_finished = 1;
  pk_initialized = 1;
  goto cleanup;

error:
  if (pk_do_init_finished) {
    if(pk_deinit() != 0){
      ERROR("pk_deinit failed");
    }
  }
cleanup:
  assert(0 == pthread_mutex_unlock(&pku_mutex));
  return child;
}
//------------------------------------------------------------------------------

#ifdef SHARED

#include <link.h>
#include <elf.h>

/**
 * Copied from RISCV-PK:
 * 
 * The protection flags are in the p_flags section of the program header.
 * But rather annoyingly, they are the reverse of what mmap expects.
 */
static int pk_get_prot(uint32_t p_flags)
{
  int prot_x = (p_flags & PF_X) ? PROT_EXEC  : PROT_NONE;
  int prot_w = (p_flags & PF_W) ? PROT_WRITE : PROT_NONE;
  int prot_r = (p_flags & PF_R) ? PROT_READ  : PROT_NONE;

  return (prot_x | prot_w | prot_r);
}
//------------------------------------------------------------------------------

typedef struct {
  int did;
  vkey_t vkey;
  const void* self;
  const char* module;
  int count;
} module_t;
//------------------------------------------------------------------------------

static int PK_CODE pk_module_reprotect_phdr(module_t* module, struct dl_phdr_info *info, Elf64_Phdr* phdr) {
  uintptr_t start = info->dlpi_addr + phdr->p_vaddr;
  uintptr_t end = start + phdr->p_memsz;
  start &= ~PAGEMASK;                   // round down
  end = (end + PAGESIZE-1) & ~PAGEMASK; // round up
  int prot = pk_get_prot(phdr->p_flags);
  int ret = pk_pkey_mprotect2(module->did, (void*)start, end - start, prot, module->vkey);
  if (-1 == ret) {
    perror("pk_pkey_mprotect failed");
    return -1;
  }
  return 0;
}
//------------------------------------------------------------------------------

static int pk_module_protect_phdr(struct dl_phdr_info *info, size_t size, void *data)
{
    int j;
    module_t* module = (module_t*)data;
    if (!module) {
      return -1;
    }
    DEBUG_MPK("pku_selfprotect_phdr(%d, %d, %p, %s)", module->did, module->vkey, module->self, module->module);
    DEBUG_MPK("Module %s (%d segments)", info->dlpi_name, info->dlpi_phnum);
    
    if (module->self) {
        DEBUG_MPK("Searching for module which covers self %p", module->self);
        // Search for module that contains our code
        for (j = 0; j < info->dlpi_phnum; j++) {
            Elf64_Phdr phdr = info->dlpi_phdr[j];
            if (phdr.p_type == PT_LOAD) {
                uintptr_t start = info->dlpi_addr + phdr.p_vaddr;
                uintptr_t end = start + phdr.p_memsz;
                if ((uintptr_t)module->self >= start && (uintptr_t)module->self < end) {
                    DEBUG_MPK("Found self module");
                    break;
                }
            }
        }
        if (j >= info->dlpi_phnum) {
            // We're in the wrong module
            DEBUG_MPK("Skipping");
            return 0;
        }
    }

    if (module->module) {
        DEBUG_MPK("Searching for module matching substring %s", module->module);
        if (strstr(info->dlpi_name, module->module)) {
            DEBUG_MPK("Found module %s", info->dlpi_name);
        } else {
            // We're in the wrong module
            DEBUG_MPK("Skipping");
            return 0;
        }
    }

    // Re-protect all PT_LOAD (+ GNU_RELRO) segments with did/vkey
    for (j = 0; j < info->dlpi_phnum; j++) {
        Elf64_Phdr phdr = info->dlpi_phdr[j];
        if (phdr.p_type == PT_LOAD) {
            DEBUG_MPK("Reprotecting PT_LOAD   %2d: address=%10p (0x%010lx) [flags 0x%x]", j, (void *) (info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz, phdr.p_flags);
            if (-1 == pk_module_reprotect_phdr(module, info, &phdr)) {
                // errno set by reprotect_phdr
                return -1;
            }
        } else if (phdr.p_type == PT_GNU_RELRO) {
            DEBUG_MPK("Reprotecting GNU_RELRO %2d [%d]: address=%10p (0x%010lx) [flags 0x%x]", j, phdr.p_type, (void *) (info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz, phdr.p_flags);
            if (-1 == pk_module_reprotect_phdr(module, info, &phdr)) {
                // errno set by reprotect_phdr
                return -1;
            }
        } else if (phdr.p_type == PT_TLS) {
            DEBUG_MPK("Ignoring     PT_TLS    %2d [%d]: address=%10p (0x%010lx) [flags 0x%x]", j, phdr.p_type, (void *) (info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz, phdr.p_flags);
        } else {
            DEBUG_MPK("Ignoring     header    %2d [%d]: address=%10p (0x%010lx) [flags 0x%x]", j, phdr.p_type, (void *) (info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz, phdr.p_flags);
        }
    }
    module->count++;
    return 0;
}
//------------------------------------------------------------------------------

int PK_API pk_module_protect(int did, vkey_t vkey, const void* self, const char* module) {
  module_t mod = {
    .did = did,        // domain to which memory shall be assigned. Can be PK_DOMAIN_CURRENT
    .vkey = vkey,      // protection key to be assigned to memory. Needs to be owned by did. Can be PK_DEFAULT_KEY
    .self = self,      // if not NULL, only protect module containing this pointer
    .module = module,  // if not NULL, only protect module matching this string
    .count = 0,        // incremented by pk_module_protect_phdr for each protected module
  };
  int ret = dl_iterate_phdr(pk_module_protect_phdr, &mod);
  if (ret < 0) {
    // errno is set by pk_module_protect_phdr
    return ret;
  }
  return mod.count;
}
//------------------------------------------------------------------------------

#endif // SHARED

#ifdef TIMING
    //_timing timing_values[NUM_TIMING_VALUES] = {{0,},};
    //size_t timing_values_index = 0;
    uint64_t PK_API timing_min = UINT64_MAX;
    uint64_t PK_API timing_tmp = 0;

    //complex timing table:
    #ifdef TIMING_MEASURE_MINIMUM
    uint64_t PK_API timing_values[TIMING_T_MAX];
    #else
    uint64_t PK_API timing_values[TIMING_T_MAX][NUM_TESTRUNS];
    #endif
    uint64_t PK_API time_in_progress = 0;

//------------------------------------------------------------------------------
#endif
