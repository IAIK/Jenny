#define _GNU_SOURCE 1 //Needed for pthread_getattr_np and for link.h
#include <pthread.h>
#include <link.h>
//#include "pk.h"
#include "pk_internal.h"
#include "sf.h"
#include "common_filters.h"
#include "erim.h"
#include "sysfilter.h"

#include <sys/resource.h> // getrlimit
//#include <unistd.h>
#include "limits.h"
#include <sys/ioctl.h>
//#include <sys/syscall.h>
//#include <ucontext.h>
//#include <sys/types.h>
//#include <sys/stat.h>
//#include <fcntl.h>

void PK_CODE _pk_my_debug_check();
//------------------------------------------------------------------------------
// Internal globals
//------------------------------------------------------------------------------
//For attributes: See also https://github.com/riscv/riscv-elf-psabi-doc/blob/master/riscv-elf.md#thread-local-storage
// We only make it PK_API to allow access tests (test5) which should fail
#ifdef SHARED
__thread PK_API _pk_tls   pk_trusted_tls   __attribute__((tls_model ("initial-exec"))) __attribute__((aligned(PAGESIZE))) = {0,};
//~ __thread PK_API _pk_rotls pk_trusted_rotls __attribute__((tls_model ("initial-exec"))) __attribute__((aligned(PAGESIZE))) = {0,};
#else
__thread PK_API _pk_tls   pk_trusted_tls   __attribute__((tls_model ("local-exec"))) __attribute__((aligned(PAGESIZE))) = {0,};
//~ __thread PK_API _pk_rotls pk_trusted_rotls __attribute__((tls_model ("local-exec"))) __attribute__((aligned(PAGESIZE))) = {0,};
#endif

uint64_t PK_DATA _pk_ttls_offset = 0;

int       PK_DATA did_root;
int       PK_DATA did_for_exception_handler;
//vkey_t    PK_DATA rokey_for_exception_handler = VKEY_INVALID;
pk_key_t  PK_DATA rokey_for_exception_handler = { //read-only key that is given to all domains
    .vkey       = VKEY_INVALID,
    .pkey       = (pkey_t)VKEY_INVALID,
    .owner      = 0,
    .perm       = 0,
    .used       = 0,
    ._reserved  = 0
};
_pk_ecall PK_DATA pk_registered_ecalls[NUM_REGISTERED_ECALLS];
_pk_data  PK_DATA PK_API pk_data = {0,};
int       PK_DATA pk_shared_pkeys[PK_NUM_KEYS] = {0,};
vkey_t    PK_DATA pk_vkey_cnt = 1;
bool      PK_DATA pk_sysfilter_module = false;
int       PK_DATA sysfilter_fd = -1;
pid_t     PK_DATA sysfilter_pid = -1;

struct sigaction PK_DATA pk_signal_action[MAX_SIGNO] = {0,};
int              PK_DATA pk_signal_did[MAX_SIGNO] = {DID_INVALID,};
//~ uint64_t*        PK_DATA pk_sigaltstack_unsafe = NULL;



// Our kernel patch ensures that the signal handler executes with elevated PKRU
// that has access to our sigaltstack. Nevertheless, give full pkru permissions
// manually to also access other monitor-protected structures, e.g., the ttls.
// Any debug statement might ruin this full-PKRU hack, so redo it
#define ENSURE_FULL_PKRU_ACCESS() do { _write_pkru_reg(0); } while(0)

//------------------------------------------------------------------------------
// DL Hooking
//------------------------------------------------------------------------------

// If the pku_lib is preloaded, we need to prevent it from also hooking
// pk_lib, otherwise we would get recursion
// To do so, we find the original symbols, bypassing pku_lib preloading.

#ifdef DL_HOOKING
#include <dlfcn.h>

void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
int   (*real_munmap)(void *addr, size_t length) = NULL;
int   (*real_madvise)(void *addr, size_t length, int advice) = NULL;
void *(*real_mremap)(void *old_address, size_t old_size,
                     size_t new_size, int flags, void *new_address) = NULL;
int   (*real_mprotect)(void *, size_t, int) = NULL;
int   (*real_pkey_alloc)(unsigned int flags, unsigned int access_rights) = NULL;
int   (*real_pkey_free)(int pkey) = NULL;
int   (*real_pkey_mprotect)(void *addr, size_t len, int prot, int pkey) = NULL;
int   (*real_sigaction)(int signum, const struct sigaction *act,
                        struct sigaction *oldact) = NULL;
sighandler_t (*real_signal)(int signum, sighandler_t handler) = NULL;
int   (*real_pthread_create)(pthread_t *thread, const pthread_attr_t *attr,
                             void *(*start_routine) (void *), void *arg) = NULL;
int   (*real_pthread_exit)(void *retval) = NULL;

int PK_CODE _pk_dl_libresolve_phdr(struct dl_phdr_info *info, size_t size, void* data)
{
  const char** name = (const char**)data;
  DEBUG_MPK("Searching for %s", *name);
  DEBUG_MPK("Resolving module %s", info->dlpi_name);
  if (strstr(info->dlpi_name, *name)) {
    *name = info->dlpi_name;
    return 1;
  }
  return 0;
}
//------------------------------------------------------------------------------

const char* PK_CODE _pk_dl_libresolve(const char* search){
  DEBUG_MPK("_pk_dl_libresolve(%p=%s)", search, search);
  const char* name = search;
  dl_iterate_phdr(_pk_dl_libresolve_phdr, &name);
  DEBUG_MPK("_pk_dl_libresolve found %s)", name);
  return name;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_dl_hooking(){
  // We hook to find the original libc functions
  // I.e. we want to bypass pku_lib preloading to avoid recursion, and
  // instead directly call to libc

  // Search for full library path
  const char* libc_path = _pk_dl_libresolve("libc.");
  const char* libpthread_path = _pk_dl_libresolve("libpthread.");

  // Open the already loaded libraries
  void* libc_handle = dlopen(libc_path, RTLD_LAZY | RTLD_NOLOAD);
  if (!libc_handle) {
    ERROR("libc could not be dlopened under %s", libc_path);
    return -1;
  }
  void* libpthread_handle = dlopen(libpthread_path, RTLD_LAZY | RTLD_NOLOAD);
  if (!libpthread_handle) {
    ERROR("libpthread could not be dlopened under %s", libpthread_path);
    return -1;
  }

  // Do symbol resolution
  // Hooking libc functions
  if (!real_mmap) {
    DEBUG_MPK("Hooking mmap\n");
    real_mmap = dlsym(libc_handle, "mmap");
    DEBUG_MPK("real_mmap: %p", real_mmap);
  }
  if (!real_munmap) {
    DEBUG_MPK("Hooking munmap\n");
    real_munmap = dlsym(libc_handle, "munmap");
    DEBUG_MPK("real_munmap: %p", real_munmap);
  }
  if (!real_madvise) {
    DEBUG_MPK("Hooking madvise\n");
    real_madvise = dlsym(libc_handle, "madvise");
    DEBUG_MPK("real_madvise: %p", real_madvise);
  }
  if (!real_mremap) {
    DEBUG_MPK("Hooking mremap\n");
    real_mremap = dlsym(libc_handle, "mremap");
    DEBUG_MPK("real_mremap: %p", real_mremap);
  }
  if (!real_mprotect) {
    DEBUG_MPK("Hooking mprotect\n");
    real_mprotect = dlsym(libc_handle, "mprotect");
    DEBUG_MPK("real_mprotect: %p", real_mprotect);
  }
  if (!real_sigaction) {
    DEBUG_MPK("Hooking sigaction\n");
    real_sigaction = dlsym(libc_handle, "sigaction");
    DEBUG_MPK("sigaction: %p", real_sigaction);
  }
  if (!real_signal) {
    DEBUG_MPK("Hooking signal\n");
    real_signal = dlsym(libc_handle, "signal");
    DEBUG_MPK("signal: %p", real_signal);
  }
  // Hooking libpthread functions
  if (!real_pthread_create) {
    DEBUG_MPK("Hooking pthread_create\n");
    real_pthread_create = dlsym(libpthread_handle, "pthread_create");
    DEBUG_MPK("real_pthread_create: %p", real_pthread_create);
  }
  if (!real_pthread_exit) {
    DEBUG_MPK("Hooking real_pthread_exit\n");
    real_pthread_exit = dlsym(libpthread_handle, "pthread_exit");
    DEBUG_MPK("pthread_exit: %p", real_pthread_exit);
  }
  if (!real_mmap ||
      !real_munmap ||
      !real_madvise ||
      !real_mremap ||
      !real_mprotect ||
      !real_sigaction ||
      !real_signal ||
      !real_pthread_create ||
      !real_pthread_exit
      ) {
  
    errno = EACCES;
    return -1;
  }
  return 0;
}

#endif // DL_HOOKING

//------------------------------------------------------------------------------
// Internal functions
//------------------------------------------------------------------------------

char * PK_CODE _mprotect_prot_to_str(int prot){
    static char buf[512];
    int len = 0;
    if (prot & PROT_READ)  len += snprintf(buf + len, sizeof(buf) - (size_t)len, "R|");
    if (prot & PROT_WRITE) len += snprintf(buf + len, sizeof(buf) - (size_t)len, "W|");
    if (prot & PROT_EXEC)  len += snprintf(buf + len, sizeof(buf) - (size_t)len, "X|");
    if (len == 0)          len += snprintf(buf + len, sizeof(buf) - (size_t)len, "NONE|");

    assert_ifdebug(len < (int)sizeof(buf));

    //trim trailing "|"
    assert(len > 1);
    buf[len - 1] = '\0';

    return buf;
}

void PK_CODE_INLINE _debug_key(pk_key_t* key) {
    assert(key);
    DEBUG_MPK("pk_key_t {");
    DEBUG_MPK("  used =%d", key->used);
    DEBUG_MPK("  vkey =%d", key->vkey);
    DEBUG_MPK("  pkey =%d", key->pkey);
    DEBUG_MPK("  owner=%d", key->owner);
    DEBUG_MPK("  perm =%d", key->perm);
    DEBUG_MPK("}");
}
//-------------------------------------------------------------------------------

void PK_CODE_INLINE _debug_range(int rid) {
    DEBUG_MPK("mprotect_t {");
    DEBUG_MPK("  used=%d  ", pk_data.ranges[rid].used);
    DEBUG_MPK("  addr=%p  ", pk_data.ranges[rid].addr);
    DEBUG_MPK("  len =%zu ", pk_data.ranges[rid].len);
    DEBUG_MPK("  prot=%d  ", pk_data.ranges[rid].prot);
    DEBUG_MPK("  vkey=%d  ", pk_data.ranges[rid].vkey);
    DEBUG_MPK("  pkey=%d  ", pk_data.ranges[rid].pkey);
    DEBUG_MPK("}");
}
//-------------------------------------------------------------------------------

size_t PK_CODE_INLINE _get_default_stack_size() {
    struct rlimit rlim;
    size_t stack_size = 0;
    if(getrlimit(RLIMIT_STACK, &rlim) != 0){
        WARNING("getrlimit failed");
        stack_size = 1024 * PAGESIZE;
    }else{
        stack_size = rlim.rlim_cur;
    }
    DEBUG_MPK("stack size = %zu KB", stack_size/1024);
    return stack_size;
}
//------------------------------------------------------------------------------

ssize_t PK_CODE_INLINE _find_in_array(int val, int* array, size_t array_count){
    for (size_t i = 0; i < array_count; i++){
        if(array[i] == val){
            return (ssize_t)i;
        }
    }
    return -1;
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _domain_is_child(int did){
    if (!_domain_exists(did)) {
      return false;
    }
    return (CURRENT_DID == pk_data.domains[did].parent_did);
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _domain_is_current_or_child(int did){
    //return (CURRENT_DID == did || _domain_is_child(did));
    return (CURRENT_DID == did || _domain_is_descendant(did)); // parent can manage all of its children and grandchildren
}
//------------------------------------------------------------------------------

PK_CODE_INLINE pk_key_t * _domain_get_pk_key_t(int did, vkey_t vkey){
    if (!_domain_exists(did)) {
      return NULL;
    }

    if(vkey == PK_DEFAULT_KEY) {
        vkey = _get_default_vkey(did);
        if(vkey == VKEY_INVALID){
            return NULL;
        }
    }

    for (size_t key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++){
        pk_key_t * pk_key = &(pk_data.domains[did].keys[key_id]);
        if (pk_key->used && pk_key->vkey == vkey) {
            return pk_key;
        }
    }
    return NULL;
}
//------------------------------------------------------------------------------

ssize_t PK_CODE_INLINE _domain_get_vkey_id(int did, vkey_t vkey){
    if (!_domain_exists(did)) {
      return -1;
    }

    for (ssize_t key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++){
        pk_key_t * pk_key = &(pk_data.domains[did].keys[key_id]);
        if (pk_key->used && pk_key->vkey == vkey) {
            return key_id;
        }
    }
    return -1;
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _domain_owns_vkey_nodidcheck(int did, vkey_t vkey){
    assert_ifdebug(_domain_exists(did));

    for (size_t key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++){
        if (pk_data.domains[did].keys[key_id].used &&
            pk_data.domains[did].keys[key_id].vkey == vkey &&
            pk_data.domains[did].keys[key_id].owner) {
            return true;
        }
    }
    return false;
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _is_allowed_source_nodidcheck(int source_did, int target_did){
    assert_ifdebug(_domain_exists(source_did));
    assert_ifdebug(_domain_exists(target_did));

    return (-1 != _find_in_array(
        source_did,
        pk_data.domains[(target_did)].allowed_source_domains,
        pk_data.domains[(target_did)].allowed_source_domains_count)
    );
}
//------------------------------------------------------------------------------

bool PK_CODE_INLINE _transition_allowed_nodidcheck(int target_did){
    if (CURRENT_DID == 0){
        DEBUG_MPK("transition allowed because current did = 0");
        return true;
    }
    if(_is_allowed_source_nodidcheck(CURRENT_DID, target_did)){
        DEBUG_MPK("current did (%d) is allowed to transition to %d", CURRENT_DID, target_did);
        return true;
    }
    return false;
}
//------------------------------------------------------------------------------

PK_CODE void * _allocate_monitor_memory(size_t size, const char* name) {
    DEBUG_MPK("Allocating monitor memory for %s, size %zx\n", name, size);
    size = ROUNDUP_PAGE(size);
    int mmap_flags = MAP_ANON | MAP_PRIVATE;
    int mmap_fd = -1;
    off_t mmap_offset = 0;
    void* mem = MMAP(NULL, size, PROT_READ | PROT_WRITE, mmap_flags, mmap_fd, mmap_offset);
    if (MAP_FAILED == mem) {
        return NULL;
    }

    DEBUG_MPK("Protecting monitor memory");
    // This function also tracks the memory
    int ret = _pk_pkey_mprotect_unlocked_nodid_check(DID_FOR_EXCEPTION_HANDLER, mem, size, PROT_WRITE | PROT_READ, PK_DEFAULT_KEY, mmap_flags, mmap_fd, mmap_offset);
    assert (0 == ret);

    _pk_name_range(mem, size, name);
    return mem;
}
//------------------------------------------------------------------------------

PK_CODE void * _allocate_stack(size_t stack_size) {
    DEBUG_MPK("Allocating stack with size %zu", stack_size);
    int ret;

    void * stack_base = MMAP(NULL, stack_size + 2*PAGESIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if(stack_base == MAP_FAILED){
        ERROR("_allocate_stack: mmap failed");
        // errno is set by mmap
        return NULL;
    }
    DEBUG_MPK("Allocated stack (incl guard) %p-%p", stack_base, stack_base + stack_size + 2*PAGESIZE);
    // stack_addr due to guard page
    void * stack_addr = (void*)((uintptr_t)stack_base + PAGESIZE);

    DEBUG_MPK("Allocated stack @ %p size 0x%zx", stack_addr, stack_size);

    // first guard page
    ret = MPROTECT(stack_base, PAGESIZE, PROT_NONE);
    if(ret != 0){
        WARNING("_allocate_stack: mprotect on first guard page failed");
        // we continue here
    }
    DEBUG_MPK("Protected bottom stack guard page @ %p", stack_base);

    // second guard page
    ret = MPROTECT((char*)stack_addr + stack_size, PAGESIZE, PROT_NONE);
    if(ret != 0){
        WARNING("_allocate_stack: mprotect on last guard page failed");
        // we continue here
    }
    DEBUG_MPK("Protected top stack guard page @ %p", (char*)stack_addr + stack_size);

    return stack_addr;
}
//------------------------------------------------------------------------------

PK_CODE int _deallocate_stack(void* stack_base, size_t stack_size) {
    uintptr_t alloced = (uintptr_t)stack_base - PAGESIZE;
    int ret = MUNMAP((void*)alloced, stack_size + 2 * PAGESIZE);
    if (0 == ret) {
        _untrack_memory((void*)alloced, stack_size + 2 * PAGESIZE);
    }
    return ret;
}
//------------------------------------------------------------------------------
  
bool PK_CODE_INLINE _address_overlaps(void* addr1, void* addr2, size_t len2) {
    return (char*)addr1 >= (char*)addr2 && 
           (char*)addr1 <  (char*)addr2 + len2;
}

//------------------------------------------------------------------------------

void PK_CODE _pk_name_range(void * addr, size_t len, const char * name) {
#ifndef RELEASE
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if(! pk_data.ranges[rid].used){
            continue;
        }
        if(! _memory_overlaps(pk_data.ranges[rid].addr, pk_data.ranges[rid].len, addr, len)) {
            continue;
        }
        //range overlaps and is valid:
        pk_data.ranges[rid].name = name;
    }
#endif
}
//------------------------------------------------------------------------------

PK_CODE_INLINE int _protect_user_stack(int did, _pk_thread_domain * data) {
    assert(data->user_stack_size);
    assert(data->user_stack_base);

    // Protect user stack
    DEBUG_MPK("Protect user stack for domain %d\n", did);
    int prot = PROT_WRITE | PROT_READ;
    //#ifndef PROXYKERNEL
    //prot |= PROT_GROWSDOWN;
    //#endif
    int ret = _pk_pkey_mprotect_unlocked_nodid_check(did, data->user_stack_base, data->user_stack_size, prot, PK_DEFAULT_KEY, 0,0,0); //TODO mmap flags
    if(ret != 0){
        _pk_print_debug_info2(data->user_stack_base, data->user_stack_size);
        //errno set by _pk_pkey_mprotect_unlocked_nodid_check
        ERROR("_protect_user_stack: failed to protect user stack %p -- %p for domain %d", 
            (void*)data->user_stack_base, 
            (void*)((uintptr_t)data->user_stack_base + data->user_stack_size), 
            did);
    }

#ifndef RELEASE
    int thread_id = 0;
    #ifndef PROXYKERNEL
        thread_id = pthread_self(); //TODO better ids?
    #endif
    char * name = sprintf_and_malloc("Dom %d: Stack for thread 0x%x", did, thread_id);
    _pk_name_range(data->user_stack_base, data->user_stack_size, name);
#endif

    return ret;
}

PK_CODE_INLINE int pk_pthread_attr_getstack(const pthread_attr_t *attr, void **stackaddr, size_t *stacksize) {
    if(pk_data.initialized){
        return pthread_attr_getstack(attr, stackaddr, stacksize);
    }

    char line[2048];
    FILE * fp = fopen("/proc/self/maps", "r");
    if(fp == NULL){
        //errno set by fopen
        ERROR_FAIL("Failed to fopen /proc/self/maps");
    }
    while (fgets(line, 2048, fp) != NULL) {
        if (strstr(line, "[stack]") == NULL)
            continue;

        DEBUG_MPK("line = %s", line);
        char * end1 = strstr(line, "-");
        char * end2 = strstr(line, " ");
        if(end1 == NULL || end2 == NULL){
            ERROR_FAIL("strstr failed.");
        }
        *end1 = '\0';
        *end2 = '\0';
        long int number1 = strtol(line,     NULL, 16);
        long int number2 = strtol(end1 + 1, NULL, 16);
        if(number1 == LONG_MIN || number1 == LONG_MAX){
            ERROR_FAIL("Could not parse number1.");
        }
        if(number2 == LONG_MIN || number2 == LONG_MAX){
            ERROR_FAIL("Could not parse number2.");
        }

        *stackaddr = (void*)number1;
        *stacksize = (uintptr_t)number2 - (uintptr_t)number1;
        assert(*stacksize > 0);
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return EINVAL;
}

PK_CODE int _prepare_user_stack_pthread(int did, _pk_thread_domain * data) {

    size_t stacksize = 0;
    unsigned char * stackaddr = 0;

    #ifdef PROXYKERNEL
        syscall(1337, &stackaddr, &stacksize);
        WARNING("stacksize = %zu", stacksize);
        assert(stackaddr >= (unsigned char *)0x70000000ULL);
        assert(stacksize >= 4096*100);
    #else
        pthread_attr_t attr;
        int s = pthread_getattr_np(pthread_self(), &attr);
        assert(s == 0);
        s = pk_pthread_attr_getstack(&attr, (void*)&stackaddr, &stacksize);
        assert(s == 0);
        DEBUG_MPK("pthread whole stack (incl. red zone): %p-%p (len = %zu = 0x%zx)", stackaddr, stackaddr + stacksize, stacksize, stacksize);

        // clip off red zone (one page)
        // http://rachid.koucha.free.fr/tech_corner/problem_of_thread_creation.html
        stackaddr += PAGESIZE;
        stacksize -= PAGESIZE;

        DEBUG_MPK("pthread stack: %p-%p (len = %zu = 0x%zx)", stackaddr, stackaddr + stacksize, stacksize, stacksize);
    #endif

    data->user_stack_size = stacksize;
    data->user_stack_base = (void*)stackaddr;
    assert(data->user_stack_size);
    assert(data->user_stack_base);
    DEBUG_MPK("retrieved pthread user_stack_base %p, size %zu", data->user_stack_base, data->user_stack_size);

    return 0;
}

PK_CODE int _allocate_user_stack(int did, _pk_thread_domain * data) {
    DEBUG_MPK("Allocating stack for thread and domain %d", did);
    assert_ifdebug(data->expected_return == 0);
    assert_ifdebug(data->user_stack_size == 0);
    assert_ifdebug(data->user_stack_base == 0);

    assert_ifdebug(PAGESIZE >= 4096);
    assert_ifdebug(pk_data.stacksize >= (size_t)100*PAGESIZE); //make sure pk_data.stacksize is properly initialized

    //~ assert_ifdebug(did != DID_FOR_ROOT_DOMAIN);
    //~ assert_ifdebug(did != DID_FOR_EXCEPTION_HANDLER);

    // Create new user stack
    data->user_stack_size = pk_data.stacksize;
    data->user_stack_base = _allocate_stack(pk_data.stacksize);

    assert(data->user_stack_size);
    assert(data->user_stack_base);

    // Protect user stack
    int ret = _protect_user_stack(did, data);
    return ret;
}
//------------------------------------------------------------------------------

PK_CODE int _deallocate_user_stack(_pk_thread_domain * data) {
    int ret = _deallocate_stack(data->user_stack_base, data->user_stack_size);
    if (0 == ret) {
        data->user_stack_base = NULL;
        data->user_stack_size = 0;
    }
    return ret;
}
//------------------------------------------------------------------------------

PK_CODE void _allocate_filter_mem(int did, pk_key_t * sysargs_key, _pk_thread_domain *data) {
    assert_ifdebug(sysargs_key->used);

    // bottom guard page + args filter_mem + top guard page
    int mmap_prot = PROT_READ | PROT_WRITE;
    int mmap_flags = MAP_ANON | MAP_PRIVATE;
    int mmap_fd = -1;
    off_t mmap_offset = 0;
    char *filter_mem = MMAP(NULL, 2 * PAGESIZE + ARGS_MEM_SIZE, mmap_prot, mmap_flags, mmap_fd, mmap_offset);
    if(filter_mem == MAP_FAILED){
        //errno set by mmap
        ERROR_FAIL("mmap of syscall args region failed");
    }
    DEBUG_MPK("sysargs page: %p-%p", filter_mem, filter_mem + 2*PAGESIZE+ARGS_MEM_SIZE);

    DEBUG_MPK("Protecting lower guard page: %p", filter_mem);
    int ret = PKEY_MPROTECT(filter_mem, PAGESIZE, PROT_NONE, sysargs_key->pkey);
    if(ret != 0){
        //errno set by mprotect
        ERROR_FAIL("pkey_mprotect of syscall args bottom guard page failed");
    }

    DEBUG_MPK("Protecting upper guard page: %p", filter_mem + PAGESIZE + ARGS_MEM_SIZE);
    ret = PKEY_MPROTECT(filter_mem + PAGESIZE + ARGS_MEM_SIZE, PAGESIZE, PROT_NONE, sysargs_key->pkey);
    if(ret != 0){
        //errno set by mprotect
        ERROR_FAIL("pkey_mprotect of syscall args bottom top guard page failed");
    }

    DEBUG_MPK("Protecting rest: %p-%p", filter_mem + PAGESIZE, filter_mem + PAGESIZE+ARGS_MEM_SIZE);
    ret = PKEY_MPROTECT(filter_mem + PAGESIZE, ARGS_MEM_SIZE, mmap_prot, sysargs_key->pkey);
    if(ret != 0){
        //errno set by mprotect
        ERROR_FAIL("pkey_mprotect of syscall args region failed");
    }
    // Do not include guard pages in tracking
    if (!_track_memory(filter_mem+PAGESIZE, ARGS_MEM_SIZE, mmap_prot, sysargs_key->vkey, sysargs_key->pkey, true, mmap_flags, mmap_fd, mmap_offset)) {
        errno = ENOMEM;
        ERROR_FAIL("_pk_pkey_mprotect_unlocked cannot track more mprotect calls");
    }
    #ifndef RELEASE
        char * name = sprintf_and_malloc("Dom %d: syscall.args", did);
        _pk_name_range(filter_mem, ARGS_MEM_SIZE + 2*PAGESIZE, name);
    #endif

    data->syscall.filter_mem = filter_mem + PAGESIZE;
}
//--------------------------------------------------------------------------------

PK_CODE int _deallocate_filter_mem(_pk_thread_domain *data) {
    if (!data->syscall.filter_mem) {
        DEBUG_MPK("No filter-mem to deinit");
        return 0;
    }
    uintptr_t alloced = (uintptr_t)data->syscall.filter_mem - PAGESIZE;
    int ret = MUNMAP((void*)alloced, ARGS_MEM_SIZE + 2 * PAGESIZE);
    if (0 == ret) {
        data->syscall.filter_mem = NULL;
        _untrack_memory((void*)alloced, ARGS_MEM_SIZE + 2 * PAGESIZE);
    }
    return ret;
}
//--------------------------------------------------------------------------------

bool PK_CODE_INLINE _user_stack_pop_allowed(_pk_thread_domain * data, uintptr_t stack_pointer, size_t size) {

    assert_ifdebug(data->user_stack_size);
    assert_ifdebug(data->user_stack_base);
    assert_ifdebug(size < data->user_stack_size);

    if(unlikely(
        stack_pointer        <  (uintptr_t)data->user_stack_base ||
        stack_pointer + size >= (uintptr_t)data->user_stack_base + data->user_stack_size
    )){
        WARNING("Pop not allowed: stack frame= (0x%lx, 0x%lx), stack = (%p,0x%lx)", 
            stack_pointer, size, data->user_stack_base, data->user_stack_size);
        return false;
    }
    return true;
}
//-------------------------------------------------------------------------------

#define MRANGE_BITS_PER_DIR 12
#define MRANGE_ENTRIES_PER_DIR (1 << MRANGE_BITS_PER_DIR)
#define MRANGE_BITMASK (MRANGE_ENTRIES_PER_DIR - 1)
typedef struct {
    uintptr_t dir[MRANGE_ENTRIES_PER_DIR];
} mrange_dir_t;
PK_DATA mrange_dir_t pk_mrange_dir; //top level directory

#define DIR_L1_IDX(addr) ((((uintptr_t)addr) >> (MRANGE_BITS_PER_DIR*3)) & MRANGE_BITMASK)
#define DIR_L2_IDX(addr) ((((uintptr_t)addr) >> (MRANGE_BITS_PER_DIR*2)) & MRANGE_BITMASK)
#define DIR_L3_IDX(addr) ((((uintptr_t)addr) >> (MRANGE_BITS_PER_DIR*1)) & MRANGE_BITMASK)

PK_CODE_INLINE mprotect_t * _mrange_get(const void * addr){
    //NOTE: these functions/structures are inspired by:
    //      https://github.com/VolSec/pku-pitfalls/blob/52125b5b/erim/src/tem/libtem/libtem_memmap.c

    mrange_dir_t * l1_dir = (mrange_dir_t*)pk_mrange_dir.dir[DIR_L1_IDX(addr)];
    if (l1_dir == NULL){
        return NULL;
    }

    mrange_dir_t * l2_dir = (mrange_dir_t*)(l1_dir->dir[DIR_L2_IDX(addr)]);
    if (l2_dir == NULL){
        return NULL;
    }

    return (mprotect_t*)(l2_dir->dir[DIR_L3_IDX(addr)]);
}

PK_CODE_INLINE mrange_dir_t * _mrange_new_dir(){
    DEBUG_MPK("_mrange_new_dir");
    void * dir = MMAP(NULL, sizeof(mrange_dir_t), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    // TODO mprotect_pkey with ro-key
    memset(dir, 0x00, sizeof(mrange_dir_t));
    return (mrange_dir_t *)dir;
}

PK_CODE_INLINE void _mrange_update_dir(void * vaddr, size_t len, mprotect_t * mprotect_range){
    void * start = vaddr;
    assert(len);
    void * end = (void*)((char*)vaddr + len - 1);

    size_t l1_start = DIR_L1_IDX(start);
    size_t l1_end   = DIR_L1_IDX(end);


    for (size_t i = l1_start; i <= l1_end; i++) {
        mrange_dir_t * l1_dir = (mrange_dir_t*)pk_mrange_dir.dir[i];
        if (l1_dir == NULL) {
            l1_dir = _mrange_new_dir();
            pk_mrange_dir.dir[i] = (uintptr_t)l1_dir;
        }

        size_t l2_start = (i == DIR_L1_IDX(start)) ? DIR_L2_IDX(start) : 0;
        size_t l2_end   = (i == DIR_L1_IDX(end))   ? DIR_L2_IDX(end)   : MRANGE_ENTRIES_PER_DIR - 1;

        for (size_t j = l2_start; j <= l2_end; j++) {
            mrange_dir_t * l2_dir = (mrange_dir_t*) l1_dir->dir[j];
            if (l2_dir == NULL) {
                l2_dir = _mrange_new_dir();
                l1_dir->dir[j] = (uintptr_t)l2_dir;
            }

            size_t l3_start = (i == DIR_L1_IDX(start) && j == DIR_L2_IDX(start)) ? DIR_L3_IDX(start) : 0;
            size_t l3_end   = (i == DIR_L1_IDX(end)   && j == DIR_L2_IDX(end))   ? DIR_L3_IDX(end)   : MRANGE_ENTRIES_PER_DIR - 1;

            for (size_t k = l3_start; k <= l3_end; k++) {
                l2_dir->dir[k] = (uintptr_t)mprotect_range;
            }
        }
    }
}

//-------------------------------------------------------------------------------

/**
 * Get an mprotect_t* pointer to the tracked memory range covering addr.
 * The pointer remains valid until the next operation affecting memory ranges.
 * 
 * @return the mprotect_t* pointer, or NULL if no corresponding address range has been tracked before
 */
PK_CODE_INLINE mprotect_t* _get_tracked_memory(const void* addr) {
    mprotect_t* ret1 = _mrange_get(addr);
#ifdef RELEASE
    return ret1;
#else
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (!pk_data.ranges[rid].used) {
            continue;
        }
        if(rid > pk_data.ranges_max_used){
            break;
        }
        if (_address_overlaps((void*)addr, pk_data.ranges[rid].addr, pk_data.ranges[rid].len)) {
            mprotect_t* ret = &pk_data.ranges[rid];
            assert(ret == ret1);
            return ret;
        }
    }
    return NULL;

#endif
}

//-------------------------------------------------------------------------------

/**
 * Unassigned memory can be owned by anyone. 
 * TODO: root domain needs to mprotect all shared libs to get their memory
 * tracked and assigned a key (0). Thus, only root domain can own it.
 */
bool PK_CODE_INLINE _domain_owns_memory(int did, const void * addr, size_t len) {
    // DEBUG_MPK("_domain_owns_memory(%d, %p, %zu)", did, addr, len);
    if (did == DID_FOR_EXCEPTION_HANDLER) {
        return true;
    }
    if (!_domain_exists(did)) {
        return false;
    }

    for(uintptr_t p = (uintptr_t)addr; p <= ((uintptr_t)addr)+len; p = (uintptr_t)p + PAGESIZE){
        mprotect_t * range = _get_tracked_memory(addr);
        if(range){
            if (!_domain_owns_vkey_nodidcheck(did, range->vkey)) {
                return false;
            }
        }
    }
    return true;
}
//-------------------------------------------------------------------------------
bool PK_CODE _pk_domain_can_access_memory_syscall(int did, const void * addr, size_t len, bool write_access) {
    // DEBUG_MPK("_pk_domain_can_access_memory(%d, %p, %zu)", did, addr, len);
    if (did == DID_FOR_EXCEPTION_HANDLER) {
        return true;
    }
    if (NULL == addr) {
        return 0;
    }
    if (!_domain_exists(did)) {
        return false;
    }
    // also syscall args key permits to access memory (in syscall)
    assert_ifdebug(pk_trusted_tls.syscall_args_key.used);
    vkey_t syscall_args_key = pk_trusted_tls.syscall_args_key.vkey;


    for(uintptr_t p = (uintptr_t)addr; p <= ((uintptr_t)addr)+len; p = (uintptr_t)p + PAGESIZE){
        mprotect_t * range = _get_tracked_memory(addr);
        if(range == NULL){ continue; }

        // Check if domain does own vkey of this memory range
        vkey_t vkey = range->vkey;
        pk_key_t *key = _domain_get_pk_key_t(did, vkey);
        DEBUG_MPK("overlap of %p with range %p", addr, range->addr);
        // domain does not have the key or not correct permissions
        // and it is also not the syscall args key
        if ((key == NULL || key->perm & PKEY_DISABLE_ACCESS || ((key->perm & PKEY_DISABLE_WRITE) && write_access))
                    && syscall_args_key != vkey) {
            return false;
        }
        // The tested address range belongs to us
        /*
        if (_memory_fully_contained(addr, len, range->addr, range->len)) {
            //early abort so that we dont have to check multiple ranges
            return true;
        }
        */
    }
    DEBUG_MPK("allow");
    return true;
}
//-------------------------------------------------------------------------------

int PK_CODE _pk_domain_can_access_string_syscall(int did, const void * addr, bool write_access) {
    if (NULL == addr) {
        return 0;
    }
    if (did == DID_FOR_EXCEPTION_HANDLER) {
        return PATH_MAX;
    }
    if (!_domain_exists(did)) {
        return 0;
    }

    assert_ifdebug(PATH_MAX <= PAGESIZE);
    size_t len = PATH_MAX;
    // also syscall args key permits to access memory (in syscall)
    assert_ifdebug(pk_trusted_tls.syscall_args_key.used);
    vkey_t syscall_args_key = pk_trusted_tls.syscall_args_key.vkey;


    for(uintptr_t p = (uintptr_t)addr; p <= ((uintptr_t)addr)+len; p = (uintptr_t)p + PAGESIZE){
        mprotect_t * range = _get_tracked_memory(addr);
        if(range == NULL){ continue; }

        // Memory range overlaps
        // Check if domain does own vkey of this memory range
        vkey_t vkey = range->vkey;
        pk_key_t *key = _domain_get_pk_key_t(did, vkey);
        DEBUG_MPK("overlap of %p with range %p", addr, range->addr);
        // domain does not have the key or not correct permissions
        // and it is also not the syscall args key
        if ((key == NULL || key->perm & PKEY_DISABLE_ACCESS || ((key->perm & PKEY_DISABLE_WRITE) && write_access))
                    && syscall_args_key != vkey) {
            // We somehow overlap with inaccessible memory
            if ((uintptr_t)addr >= (uintptr_t)range->addr) {
                // Our start address is already inaccessible
                return 0;
            } else {
                // Our start address is accessible

                //limit len to end of range:
                uintptr_t end = (uintptr_t)addr + len;
                uintptr_t end_of_range = (uintptr_t)range->addr + range->len;
                if(end > end_of_range){
                    len = end_of_range - (uintptr_t)addr;
                    if(len > PATH_MAX){
                        len = PATH_MAX;
                    }
                }
                return len;
            }
        }


    }
    DEBUG_MPK("allow");
    return len;
}
//------------------------------------------------------------------------------

vkey_t PK_CODE_INLINE _vkey_for_address_no_permission_check(void * addr) {
    mprotect_t* range = _get_tracked_memory(addr);
    if(range == NULL){
        return 0;
    }
    vkey_t vkey = range->vkey;
    assert_ifdebug(VKEY_INVALID != vkey);
    return vkey;
}
//-------------------------------------------------------------------------------

// returns -1 on error
vkey_t PK_CODE_INLINE _vkey_for_address_nodidcheck(int did, void * addr) {
    // DEBUG_MPK("_key_for_address(%d, %p)", did, addr);
    assert_ifdebug(_domain_exists(did));

    vkey_t vkey = _vkey_for_address_no_permission_check(addr);
    if (_domain_has_vkey_nodidcheck(did, vkey)) {
        return vkey;
    }
    return VKEY_INVALID;
}
//------------------------------------------------------------------------------

/**
 * @brief This function handles missing-key-exception
 */
int PK_CODE _pk_exception_key_mismatch_unlocked(void * bad_addr){
    DEBUG_MPK("_pk_exception_key_mismatch_unlocked(%p)", bad_addr);
    // keys are assigned on a page granularity
    // Yet, bad_addr could span two different keys on a page border
    // Load both of them
    static PK_DATA void * pk_previous_badaddr = NULL;
    static PK_DATA size_t pk_previous_badctr = 0;

    //ERROR("current did = %d", CURRENT_DID);
    //ERROR("pk_previous_badaddr = %p", pk_previous_badaddr);
    //ERROR("pk_previous_badctr = %lx", pk_previous_badctr);

    if (pk_previous_badaddr == bad_addr) {
        pk_previous_badctr++;
        if (pk_previous_badctr >= 3) {
            ERROR("Triple fault. Giving up");
            pk_previous_badctr = 0;
            errno = EPERM;
            return -1;
        }
    } else {
        pk_previous_badctr = 1;
        pk_previous_badaddr = bad_addr;
    }

    vkey_t vkey1 = _vkey_for_address_nodidcheck(CURRENT_DID, bad_addr);
    char* top_addr = (char*)bad_addr+WORDSIZE-1;
    vkey_t vkey2 = vkey1;
    //maybe different vkey if not on the same page
    if( (uintptr_t)top_addr / PAGESIZE != (uintptr_t)bad_addr / PAGESIZE ){
        vkey2 = _vkey_for_address_nodidcheck(CURRENT_DID, top_addr);
    }
    //ERROR("vkeys = %d %d", vkey1, vkey2);

#ifndef RELEASE
    //TODO use _get_tracked_memory but consider that we have two matching ranges
    for (size_t range_id = 0; range_id < NUM_MPROTECT_RANGES; range_id++) {
        mprotect_t range = pk_data.ranges[range_id];
        if (!range.used){ continue; }
        if(! _memory_overlaps(bad_addr, WORDSIZE, range.addr, range.len)){ continue; }
        ERROR("%4zu: addr=%16p -- %16p, len=0x%8zx, prot=%2d %-5s, key=%2d-%2d. %s", 
            range_id, range.addr, 
            (void*)((uintptr_t)range.addr + range.len), 
            range.len, range.prot, _mprotect_prot_to_str(range.prot), 
            range.pkey, range.vkey,
            range.name ? range.name : ""
        );
    }
#endif /* RELEASE */


    if (VKEY_INVALID == vkey1 || VKEY_INVALID == vkey2) {
        ERROR("domain %s does not own pkeys for [%p-%p]", _pk_domain_str(CURRENT_DID), bad_addr, top_addr);
#ifdef RELEASE /* ifdef because the range is already printed above in case of DEBUG mode */
        ERROR("Affected Memory ranges:");
        //TODO use _get_tracked_memory but consider that we have two matching ranges
        for (size_t range_id = 0; range_id < NUM_MPROTECT_RANGES; range_id++) {
            mprotect_t range = pk_data.ranges[range_id];
            if (!range.used){ continue; }
            if(! _memory_overlaps(bad_addr, WORDSIZE, range.addr, range.len)){ continue; }
            ERROR("%4zu: addr=%16p -- %16p, len=0x%8zx, prot=%2d %-5s, key=%2d-%2d. %s", 
                range_id, range.addr, 
                (void*)((uintptr_t)range.addr + range.len), 
                range.len, range.prot, _mprotect_prot_to_str(range.prot), 
                range.pkey, range.vkey,
                range.name ? range.name : ""
            );
        }
#endif /* RELEASE */
        errno = EPERM;
        return -1;
    }

    pkru_config_t pkru_before = read_pkru_current_thread(CURRENT_DID);

    if ( 0 != _pk_domain_load_key_unlocked(CURRENT_DID, vkey1, PK_SLOT_ANY, 0) ){
        ERROR("failed to load vkey1");
        // errno is set by _pk_domain_load_key
        return -1;
    }
    if (vkey2 != vkey1 && 0 != _pk_domain_load_key_unlocked(CURRENT_DID, vkey2, PK_SLOT_ANY, 0) ){
        ERROR("failed to load vkey2");
        // errno is set by _pk_domain_load_key
        return -1;
    }

    //if we actually loaded a key (or changed permissions of a key) then do not increment the badctr.
    pkru_config_t pkru_after = read_pkru_current_thread(CURRENT_DID);
    if(PKRU_TO_INT(pkru_after) != PKRU_TO_INT(pkru_before)){
        pk_previous_badctr--;
    }else{
        ERROR("Unable to resolve exception");
        pk_previous_badctr = 0;
        errno = EPERM;
        return -1;
    }

    return 0;
}
//------------------------------------------------------------------------------

/**
 * @brief This function handles ecalls and returns.
 * 
 * @param type
 *        @c TYPE_ECALL: Stores return information such as the @p reentry
 *            point in an @c _expected_return frame on the caller's stack
 *            The caller DID is pushed on the target's stack.
 *        @c TYPE_RET: Retrieves the original caller DID from current user
 *            stack, and recover the @c _expected_return frame from the
 *            original caller stack
 * @return
 *        Returns the @p type again
 */
uint64_t PK_CODE _pk_exception_handler_unlocked(uint64_t data, uint64_t id, uint64_t type, uint64_t * current_stack, void * reentry){
    DEBUG_MPK("_pk_exception_handler_c(id=%zu, type=%zu=%s, reentry=%p)",
        id, type, type_str(type), reentry);
    assert_ifdebug(pk_data.initialized);
    assert_ifdebug(!pk_trusted_tls.filter_syscalls);
    assert_ifdebug(pk_trusted_tls.init);
    assert_ifdebug(!pk_trusted_tls.exiting);

    #if defined(TIMING) && defined(DEBUG)
    pk_data.stat_num_exceptions = pk_data.stat_num_exceptions + 1;
    #endif

    //Note: the reentry argument is only valid for type == TYPE_CALL


    int    current_did = CURRENT_DID;
    DEBUG_MPK("    current_did = 0x%x", current_did);

    if(type == TYPE_CALL){
        // Resolve ecall ID
        if(unlikely(id >= NUM_REGISTERED_ECALLS)){
            errno = EINVAL;
            ERROR_FAIL("ecall %zu not registered (out of range)", id);
        }
        void * entry      = pk_registered_ecalls[id].entry;
        int    target_did = pk_registered_ecalls[id].did;
        char * name       = pk_registered_ecalls[id].name;

        // check if id is registered
        if(unlikely(entry == 0)){
            errno = EINVAL;
            ERROR_FAIL("ecall %zu not registered!", id);
        }
        // Since entry exists, also target_did is valid

        DEBUG_MPK("    target_did  = 0x%x", target_did);
        DEBUG_MPK("    entry       = %p %s", entry, name);

        // check arguments
        assert_ifdebug(reentry              != 0);
        assert_ifdebug(current_stack        != 0);

        // check if call transition allowed
        if(unlikely(!_transition_allowed_nodidcheck(target_did))){
            errno = EPERM;
            ERROR_FAIL("call transition from %d to %d not allowed", current_did, target_did);
        }

        //get thread-domain data
        _pk_thread_domain * target_thread_domain  = _pk_get_thread_domain_data_nodidcheck(target_did);

        // Load target stack pointer
        uint64_t * target_stack = 0;
        if(unlikely(target_thread_domain->expected_return)){
            // this is a nested call
            // stack is exactly where the last excepted_return struct lies
            target_stack = (uint64_t *) target_thread_domain->expected_return;
        }else{
            // not a nested call
            target_stack = (uint64_t *) GET_STACK_TOP(target_thread_domain);
        }
#ifdef __x86_64__
        assert_ifdebug(((uintptr_t)target_stack % 16) == 0); // target_stack must be aligned
#endif
        assert_ifdebug(target_stack != 0);
        DEBUG_MPK("current_stack: %p, target stack: %p", current_stack, target_stack);
        // Check if there's enough space on target stack for pushing _return_did
        if(unlikely(!_user_stack_push_allowed(target_thread_domain, (uintptr_t)target_stack, sizeof(_return_did)))) {
            errno = ENOSPC;
            ERROR_FAIL("invalid target stack pointer, or not enough space");
        }

        _pk_thread_domain * current_thread_domain = &(pk_trusted_tls.thread_dom_data[current_did]);
        // Check if there's enough space on current stack
        // for pushing expected_return struct
        if(unlikely(!_user_stack_push_allowed(current_thread_domain, (uintptr_t)current_stack, sizeof(_expected_return)))) {
            errno = ENOSPC;
            ERROR_FAIL("invalid current stack pointer or not enough space");
        }

        // At this point, all the checks are passed. we're allowed to make the ecall

        // Push expected_return struct onto current stack
        _expected_return* expected_return = (_expected_return*)current_stack - 1;
#ifdef __x86_64__
        assert_ifdebug(((uintptr_t)expected_return % 16) == 0); // expected_return must be aligned
#endif
        expected_return->did      = target_did;
        expected_return->reentry  = reentry;
        expected_return->previous = current_thread_domain->expected_return;
        #ifdef ADDITIONAL_DEBUG_CHECKS
            expected_return->sp     = current_stack;
            expected_return->cookie = 0xDEADC0FEULL;
        #endif
        current_thread_domain->expected_return = expected_return;


        // Push caller DID onto target stack.
        // This is needed so that we know to which domain we want to return to.
        _return_did * ret_did = (_return_did*)target_stack - 1; //allocate _return_did struct on target stack
        target_stack = (uint64_t*)ret_did;
        ret_did->did = current_did;
        #ifdef ADDITIONAL_DEBUG_CHECKS
            ret_did->cookie1 = 0xDEADC0DEULL;
            ret_did->cookie2 = 0xDEADC0CEULL;
        #endif

        #ifdef ADDITIONAL_DEBUG_CHECKS
            assert_warn(current_did != target_did);
        #endif

        current_thread_domain->user_stack = (uint64_t *)expected_return;
#ifdef __x86_64__
        assert_ifdebug(((uintptr_t)current_thread_domain->user_stack % 16) == 0); // expected_return must be aligned
#endif

        // Switch stacks and protection keys and prepare entry address
        _pk_domain_switch(type, target_did, entry, target_stack);

    //--------------------------------------------------------------------------
    }else if(type == TYPE_RET){

        //get thread-domain data
        _pk_thread_domain * current_thread_domain = &(pk_trusted_tls.thread_dom_data[current_did]);


        // Discard 1 element from the stack, which is the return address that we no longer need
        // Check if current stack is valid for popping return address
        if(unlikely(!_user_stack_pop_allowed(current_thread_domain, (uintptr_t)current_stack, sizeof(*current_stack)))) {
            errno = EINVAL;
            ERROR_FAIL("invalid current stack pointer");
        }
        #ifdef ADDITIONAL_DEBUG_CHECKS
            //The discarded element should be the original return value from the ecall.
            //It should be very close to the original entry point of the ecall
            assert((uintptr_t)*current_stack > (uintptr_t)pk_registered_ecalls[id].entry && (uintptr_t)*current_stack < (uintptr_t)pk_registered_ecalls[id].entry + 100);
        #endif
        current_stack += 1;

        // Check if current stack is valid for popping _return_did
        if(unlikely(!_user_stack_pop_allowed(current_thread_domain, (uintptr_t)current_stack, sizeof(_return_did)))) {
            errno = EINVAL;
            ERROR_FAIL("invalid stack pointer");
        }

        // When returning, the stack pointer should now point to the _return_did struct
        _return_did * ret_did = (_return_did*)current_stack;
        int target_did = ret_did->did;
        #ifdef ADDITIONAL_DEBUG_CHECKS
            assert(ret_did->cookie1 == 0xDEADC0DEULL);
            assert(ret_did->cookie2 == 0xDEADC0CEULL);
        #endif
        DEBUG_MPK("    target_did  = 0x%x", target_did);

        // check if target_did is valid
        if(unlikely(!_domain_exists(target_did))){
            errno = EINVAL;
            ERROR_FAIL("Target domain does not exist");
        }

        // get thread-domain data for target did
        _pk_thread_domain * target_thread_domain = &(pk_trusted_tls.thread_dom_data[target_did]);

        // check if target stack is valid
        _expected_return* expected_return = target_thread_domain->expected_return;
        if(unlikely(expected_return == 0)){
            errno = EINVAL;
            ERROR_FAIL("Target domain is not expecting a return");
        }

        // Check if target stack is valid for popping _expected_return struct
        // This is very unlikely to fail, because this is already checked when making the ECALL
        if(unlikely(!_user_stack_pop_allowed(target_thread_domain, (uintptr_t)expected_return, sizeof(_expected_return)))) {
            errno = EINVAL;
            ERROR_FAIL("invalid target stack pointer");
        }

        // check if return transition allowed
        if(unlikely(expected_return->did != current_did)) {
            errno = EINVAL;
            ERROR_FAIL("Target domain (%d) is not expecting a return from the current domain (%d) ", target_did, current_did);
        }

        // Retrieve original reentry point and stack pointer
        void *     new_reentry     = expected_return->reentry;          // Warning: shadowing function argument with same name
        uint64_t * target_stack    = (uint64_t *)(expected_return + 1); // sp = where expected_return was, "minus" the struct itself
        assert_ifdebug(target_stack != 0);
        #ifdef ADDITIONAL_DEBUG_CHECKS
            assert(expected_return->cookie == 0xDEADC0FEULL);
            assert(expected_return->sp     == expected_return + 1);
            assert(expected_return->sp     == target_stack);
        #endif

        // Restore previous expected_return frame
        target_thread_domain->expected_return = expected_return->previous;

        #ifdef ADDITIONAL_DEBUG_CHECKS
            assert_warn(current_did != target_did);
        #endif

        current_thread_domain->user_stack = (uint64_t *)(ret_did+1); // pop ret_did and restore original stack
        DEBUG_MPK("current_thread_domain->user_stack = %p", current_thread_domain->user_stack);
#ifdef __x86_64__
        assert_ifdebug(((uintptr_t)current_thread_domain->user_stack % 16) == 0);
#endif
        // Switch stacks and protection keys and prepare reentry address
        _pk_domain_switch(type, target_did, new_reentry, target_stack);

    }else if(type == TYPE_API){
        errno = ENOSYS;
        ERROR_FAIL("TYPE_API should have been handled in assembly already");
    }else{
        errno = ENOSYS;
        ERROR_FAIL("Unhandled case in pk_exception_handler_c");
    }

    return type;
}
//------------------------------------------------------------------------------

#define IN_RANGE(start,x,end) ((start) <= (x) && (x) < (end))
#define IN_PK_CODE(x) IN_RANGE((uintptr_t)__start_pk_code, (uintptr_t)(x), (uintptr_t)__stop_pk_code)
//------------------------------------------------------------------------------

void PK_CODE_INLINE _init_debug(){
    int ret;
    debug_buffer_process_private = MMAP(0, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert(MAP_FAILED != debug_buffer_process_private);
    ret = MADVISE(debug_buffer_process_private, 4096, MADV_WIPEONFORK); //clear some buffer for children such that we know that we're a child and can get new getpid stuff
    assert(0 == ret);

    #ifndef RELEASE
        /*Otherwise some output might not be displayed*/
        setbuf(stdout, NULL);
        setbuf(stderr, NULL);
    #endif

    assert(WORDSIZE == sizeof(uint64_t));

    #ifndef SHARED
    #ifdef ADDITIONAL_DEBUG_CHECKS

        /*
        _pk_.* some of these have respective API wrapper functions without underscore
        _[^p][^k]_.* are protected internal functions
        pk_.* are protected and don't have a wrapper
            ... except for a few which are unprotected and have no wrapper
                because we don't use them internally and they don't have to
                access priviledged pk data
        */
        assert(IN_PK_CODE(_pk_init                    ));
        assert(IN_PK_CODE(_pk_domain_create_unlocked  ));
        //assert(IN_PK_CODE(_pk_exception_handler       ));
        assert(IN_PK_CODE(_pk_exception_handler_arch_c));
        assert(IN_PK_CODE(_pk_exception_handler_unlocked  ));
        assert(IN_PK_CODE(_pk_setup_exception_handler_arch));
        assert(IN_PK_CODE(_pk_setup_exception_stack_arch));
        assert(IN_PK_CODE(_pk_init_arch               ));
        assert(IN_PK_CODE(_pk_setup_thread_exception_stack));
        assert(IN_PK_CODE(_pk_init_thread             ));

        assert(IN_PK_CODE(_pk_domain_switch_arch      ));
        assert(IN_PK_CODE(_get_default_vkey           ));
        assert(IN_PK_CODE(_transition_allowed_nodidcheck));
        assert(IN_PK_CODE(_get_default_stack_size     ));


        // API functions internal
        assert(IN_PK_CODE(_pk_init                    ));
        assert(IN_PK_CODE(_pk_domain_create           ));
        assert(IN_PK_CODE(_pk_domain_free             ));
        assert(IN_PK_CODE(_pk_pkey_alloc              ));
        assert(IN_PK_CODE(_pk_pkey_free               ));
        assert(IN_PK_CODE(_pk_domain_assign_pkey      ));
        assert(IN_PK_CODE(_pk_pkey_mprotect           ));
        assert(IN_PK_CODE(_pk_pkey_mprotect2          ));
        assert(IN_PK_CODE(_pk_mmap                    ));
        assert(IN_PK_CODE(_pk_munmap                  ));
        assert(IN_PK_CODE(_pk_madvise                 ));
        assert(IN_PK_CODE(_pk_domain_register_ecall   ));
        assert(IN_PK_CODE(_pk_domain_register_ecall2  ));
        assert(IN_PK_CODE(_pk_domain_register_ecall3  ));
        assert(IN_PK_CODE(_pk_domain_allow_caller     ));
        assert(IN_PK_CODE(_pk_domain_allow_caller2    ));
        assert(IN_PK_CODE(_pk_current_did             ));
        assert(IN_PK_CODE(_pk_print_debug_info        ));
        assert(IN_PK_CODE(_pk_pthread_create          ));
        assert(IN_PK_CODE(_pk_pthread_exit            ));

        // API functions external
        assert(! IN_PK_CODE(pk_print_current_reg       ));

        assert(! IN_PK_CODE(pk_init                    ));
        assert(! IN_PK_CODE(pk_domain_create           ));
        assert(! IN_PK_CODE(pk_domain_free             ));
        assert(! IN_PK_CODE(pk_pkey_alloc              ));
        assert(! IN_PK_CODE(pk_pkey_free               ));
        assert(! IN_PK_CODE(pk_domain_assign_pkey      ));
        assert(! IN_PK_CODE(pk_pkey_mprotect           ));
        assert(! IN_PK_CODE(pk_pkey_mprotect2          ));
        assert(! IN_PK_CODE(pk_mmap                    ));
        assert(! IN_PK_CODE(pk_munmap                  ));
        assert(! IN_PK_CODE(pk_madvise                 ));
        assert(! IN_PK_CODE(pk_domain_register_ecall   ));
        assert(! IN_PK_CODE(pk_domain_register_ecall2  ));
        assert(! IN_PK_CODE(pk_domain_register_ecall3  ));
        assert(! IN_PK_CODE(pk_domain_allow_caller     ));
        assert(! IN_PK_CODE(pk_domain_allow_caller2    ));
        assert(! IN_PK_CODE(pk_current_did             ));
        assert(! IN_PK_CODE(pk_print_debug_info        ));
        assert(! IN_PK_CODE(pk_pthread_create          ));
        assert(! IN_PK_CODE(pk_pthread_exit            ));

    #endif
    #endif
    print_maps();

}
//------------------------------------------------------------------------------

void* PK_CODE _pk_setup_thread_exception_stack(){
    DEBUG_MPK("_pk_setup_thread_exception_stack");

    // protect exception handler stack for this thread
    DEBUG_MPK("Allocating exception stack");
    size_t size = EXCEPTION_STACK_WORDS * WORDSIZE;
    void * exception_stack = _allocate_stack(size);
    if (!exception_stack) {
      DEBUG_MPK("_pk_setup_thread_exception_stack failed to allocate stack");
      return NULL;
    }
    DEBUG_MPK("Protecting exception stack");
    // This tracks the memory
    int ret = _pk_pkey_mprotect_unlocked_nodid_check(DID_FOR_EXCEPTION_HANDLER, exception_stack, size, PROT_WRITE | PROT_READ, PK_DEFAULT_KEY, 0,0,0); //TODO mmap flags
    assert(ret == 0);

#ifndef RELEASE
    int thread_id = 0;
    #ifndef PROXYKERNEL
        thread_id = pthread_self(); //TODO better ids?
    #endif
    char * name = sprintf_and_malloc("E-Stack for thread 0x%x", thread_id);
    _pk_name_range(exception_stack, size, name);
#endif

    return exception_stack;
}
//------------------------------------------------------------------------------

FORCE_INLINE void _get_current_ttls_range(uintptr_t* ttls_start, uintptr_t* ttls_end){
    *ttls_start = (uintptr_t)&pk_trusted_tls.backup_user_stack;
    *ttls_end  = (uintptr_t)(&pk_trusted_tls+1);
#ifdef TLS_MISALIGNMENT_BUG
    DEBUG_MPK("Misaligned TTLS from %p to %p", (void*)*ttls_start, (void*)*ttls_end);
    *ttls_start = ROUNDUP_PAGE(*ttls_start);
    *ttls_end = ROUNDDOWN_PAGE(*ttls_end-2);  // We need to misalign it from a page boundary, otherwise compiler will optimize ROUNDDOWN_PAGE away
#endif
}
//------------------------------------------------------------------------------

//~ FORCE_INLINE void _get_current_trotls_range(uintptr_t* trotls_start, uintptr_t* trotls_end){
    //~ *trotls_start = (uintptr_t)&pk_trusted_rotls.asm_pkru;
    //~ *trotls_end  = (uintptr_t)(&pk_trusted_rotls+1);
//~ #ifdef TLS_MISALIGNMENT_BUG
    //~ DEBUG_MPK("Misaligned TroTLS from %p to %p", (void*)*trotls_start, (void*)*trotls_end);
    //~ *trotls_start = ROUNDUP_PAGE(*trotls_start);
    //~ *trotls_end = ROUNDDOWN_PAGE(*trotls_end-2);  // We need to misalign it from a page boundary, otherwise compiler will optimize ROUNDDOWN_PAGE away
//~ #endif
//~ }
//------------------------------------------------------------------------------

// This function init-protects the currently running thread (TLS, etc)
// It must not use CURRENT_DID but only @p did
int PK_CODE _pk_init_thread(int did, void* exception_stack){
    DEBUG_MPK("_pk_init_thread");
    #if !defined(RELEASE) && defined(__riscv)
    pk_print_current_reg();
    PRINT_UREGS();
    #endif

    pk_trusted_tls.current_did = DID_INVALID;

    // search for free tid slot
    size_t tid = 0;
    for (tid = 0; tid < NUM_THREADS; tid++) {
      if (THREAD_UNUSED == pk_data.threads[tid]) {
        break;
      }
    }
    if (NUM_THREADS == tid) {
        ERROR("_pk_init_thread: No more threads available");
        errno = ENOMEM;
        return -1;
    }
    assert(THREAD_UNUSED == pk_data.threads[tid]);

    // protect user stack
    // Since the new TLS  is not yet protected, we need a local copy of the thread-domain-data
    _pk_thread_domain data = {0};

    // we need to mprotect user stack before trusted TLS, since trusted TLS
    // can reside within the stack range, but has more strict permission
    int ret = _prepare_user_stack_pthread(did, &data);
    if(ret != 0){
        ERROR("_pk_init_thread: _prepare_user_stack_pthread failed");
        errno = EACCES;
        return -1;
    }

    #define TCB_SIZE (0x700)

    DEBUG_MPK("tls:   %p", (void*)GET_TLS_POINTER);
    DEBUG_MPK("ttls:  %p", &pk_trusted_tls);
    DEBUG_MPK("TLS offset = 0x%lx (%ld)", _pk_ttls_offset, _pk_ttls_offset);

    assert(_pk_ttls_offset == (uint64_t)&pk_trusted_tls.backup_user_stack - GET_TLS_POINTER);

#ifdef FAKE_TLS_SWAP
#ifndef SHARED
    // Determine size of static TLS and TCB
#ifdef __x86_64__
    uintptr_t static_tls_size = ROUNDUP_PAGE(__tls_static_end) - ROUNDDOWN_PAGE(__tls_static_start);  // multiples of a page
    uintptr_t static_tls_start = ROUNDDOWN_PAGE(GET_TLS_POINTER - static_tls_size);
    uintptr_t static_tls_end = ROUNDUP_PAGE(GET_TLS_POINTER + TCB_SIZE); // TLS pointer is inbetween TLS and TCB
#else // RISC-V
    uintptr_t static_tls_size = ROUNDUP_PAGE(__tls_static_end) - ROUNDDOWN_PAGE(__tls_static_start);  // multiples of a page
    uintptr_t static_tls_start = ROUNDDOWN_PAGE(GET_TLS_POINTER - TCB_SIZE);
    uintptr_t static_tls_end = ROUNDUP_PAGE(GET_TLS_POINTER + static_tls_size);
#endif /* __x86_64 / RISC-V */
    DEBUG_MPK("static tls size:  0x%lx\n", static_tls_size);
    DEBUG_MPK("static tls start: 0x%lx", static_tls_start);
    DEBUG_MPK("       tls end:   0x%lx", static_tls_end);
    assert((uintptr_t)&pk_trusted_tls >= static_tls_start && (uintptr_t)&pk_trusted_tls <= (uintptr_t)static_tls_end);

    // Unprotect TLS such that one thread can access it in all domains
    //Note: PKEY_MPROTECT doesn't track memory. (nobody can claim it)
    ret = PKEY_MPROTECT((void*)static_tls_start, static_tls_end - static_tls_start, PROT_WRITE | PROT_READ, KEY_FOR_UNPROTECTED);
    if(ret != 0){
        //errno set by mprotect
        ERROR_FAIL("_pk_init_thread: pkey_mprotect failed");
    }

#else // SHARED
    // If shared, TLS is not located in user stack which we just protected
    // So there is no need to unprotect it
#endif // !SHARED
#else // FAKE_TLS_SWAP
    #error "Implement me"
#endif // FAKE_TLS_SWAP

    // protect trusted TLS
    uintptr_t ttls_start, ttls_end;
    _get_current_ttls_range(&ttls_start, &ttls_end);
    DEBUG_MPK("protecting TTLS from %p to %p", (void*)ttls_start, (void*)ttls_end);
    assert_ifdebug(rokey_for_exception_handler.vkey != VKEY_INVALID);
    ret = _pk_pkey_mprotect_unlocked_nodid_check(DID_FOR_EXCEPTION_HANDLER, (void*)ttls_start, ttls_end - ttls_start, PROT_WRITE | PROT_READ, rokey_for_exception_handler.vkey, 0,0,0); //TODO mmap flags
    assert(ret == 0);
    
    // write-protect trusted read-only TLS
    //~ uintptr_t trotls_start, trotls_end;
    //~ _get_current_trotls_range(&trotls_start, &trotls_end);
    //~ DEBUG_MPK("protecting TroTLS from %p to %p", (void*)trotls_start, (void*)trotls_end);
    //~ ret = _pk_pkey_mprotect_unlocked_nodid_check(DID_FOR_EXCEPTION_HANDLER, (void*)trotls_start, trotls_end - trotls_start, PROT_WRITE | PROT_READ, rokey_for_exception_handler.vkey, 0,0,0); //TODO mmap flags
    //~ assert(ret == 0);

#ifndef RELEASE
    int thread_id = 0;
    #ifndef PROXYKERNEL
        thread_id = pthread_self(); //TODO better ids?
    #endif
    char * name = sprintf_and_malloc("TTLS for thread 0x%x", thread_id);
    _pk_name_range((void *)ttls_start, ttls_end - ttls_start, name);
    //~ char * name2 = sprintf_and_malloc("TroTLS for thread 0x%x", thread_id);
    //~ _pk_name_range((void *)trotls_start, trotls_end - trotls_start, name2);
#endif

    // initialize trusted TLS
    memset(&pk_trusted_tls, 0, sizeof(pk_trusted_tls));
    //~ memset(&pk_trusted_rotls, 0, sizeof(pk_trusted_rotls));
    pk_data.threads[tid] = &pk_trusted_tls;
    pk_trusted_tls.tid = tid;
    pk_trusted_tls.thread_dom_data[did] = data;
    pk_trusted_tls.current_did = did; // Now we can use CURRENT_DID
    pk_trusted_tls.init = true;
    pk_trusted_tls.pthread_tid = (uint64_t)pthread_self();
    #ifndef PROXYKERNEL
        pk_trusted_tls.gettid = syscall(SYS_gettid);
    #else
        pk_trusted_tls.gettid = 0;
    #endif
    assert(did == CURRENT_DID);

    // architecture-specific per-thread code
    _pk_setup_exception_stack_arch(exception_stack);
    _pk_setup_exception_handler_arch();

    // allocate key just for syscall arguments
    vkey_t sysargs_vkey = _pk_pkey_alloc_unlocked(did, 0, 0); //this key belongs to the parent domain.
    if (sysargs_vkey < 0) {
        //errno set by pkey_alloc
        ERROR("could not allocate syscall key");
        return -1;
    }
    ssize_t vkid = _domain_get_vkey_id(did, sysargs_vkey);
    if (-1 == vkid) {
        ERROR("could not find syscall key");
        return -1;
    }

    // Transfer ownership of key from domain to thread since the
    // same syscall_args_key is used during nested filtering for the whole
    // thread.
    pk_trusted_tls.syscall_args_key = pk_data.domains[did].keys[vkid];
    pk_data.domains[did].keys[vkid].used = false;

    // Allocate signal stack
    pk_trusted_tls.signal_state = SIGNAL_NONE;
    pk_trusted_tls.signal_siginfo = NULL;
    //~ pk_trusted_tls.signal_siginfo = _allocate_monitor_memory(sizeof(siginfo_t), "siginfo");
    //~ if (!pk_trusted_tls.signal_siginfo) {
      //~ DEBUG_MPK("failed to allocate siginfo");
      //~ return -1;
    //~ }
    pk_trusted_tls.signal_sigframe = NULL;
    // We let it point to the (should-be) protected sigaltstack
    //~ pk_trusted_tls.signal_sigframe = _allocate_monitor_memory(sizeof(ucontext_t), "sigframe");
    //~ if (!pk_trusted_tls.signal_sigframe) {
      //~ DEBUG_MPK("failed to allocate sigframe");
      //~ return -1;
    //~ }

    // initialize PKRU
    _pk_setup_default_config_for_thread(did, &pk_trusted_tls);

    //set sigaltstack for this thread
    DEBUG_MPK("Creating new sigaltstack for this thread");
#ifdef SIGNAL_PKRU_KERNEL_PATCH

#define SS_PKEY_SHIFT       20

    vkey_t vkey = _get_default_vkey(DID_FOR_EXCEPTION_HANDLER);
    pkey_t pkey = _vkey_to_pkey(DID_FOR_EXCEPTION_HANDLER, vkey);
    pk_trusted_tls.sigaltstack.ss_flags = pkey << SS_PKEY_SHIFT;
#else
    pk_trusted_tls.sigaltstack.ss_flags = 0;
#endif
    pk_trusted_tls.sigaltstack.ss_size = 2 * SIGSTKSZ;
    pk_trusted_tls.sigaltstack.ss_sp = _allocate_stack(pk_trusted_tls.sigaltstack.ss_size);
    if (MAP_FAILED == pk_trusted_tls.sigaltstack.ss_sp) {
        ERROR("failed to map memory");
        memset(&pk_trusted_tls.sigaltstack, 0, sizeof(stack_t));
        // errno is set by mmap
        return -1;
    }

#ifdef SIGNAL_PKRU_KERNEL_PATCH
    if (-1 == _pk_pkey_mprotect_unlocked_nodid_check(DID_FOR_EXCEPTION_HANDLER, pk_trusted_tls.sigaltstack.ss_sp, pk_trusted_tls.sigaltstack.ss_size, PROT_READ | PROT_WRITE, PK_DEFAULT_KEY, 0, 0, 0)) {
        ERROR("protecting sigaltstack failed");
        // errno set by _pk_pkey_mprotect_unlocked_nodid_check
        return -1;
    }
#endif

    if (!_track_memory(pk_trusted_tls.sigaltstack.ss_sp, pk_trusted_tls.sigaltstack.ss_size, PROT_READ | PROT_WRITE, 0, 0, false, 0, 0, 0)) {
        ERROR("_track_memory failed");
        errno = ENOMEM;
        return -1;
    }

    #ifndef RELEASE
    _pk_name_range(pk_trusted_tls.sigaltstack.ss_sp, pk_trusted_tls.sigaltstack.ss_size, sprintf_and_malloc("sigaltstack for thread 0x%x", thread_id));
    #endif

    if (sigaltstack(&pk_trusted_tls.sigaltstack, NULL) == -1) {
        ERROR("sigaltstack failed");
        ERROR("Did you forget to patch the kernel with PKU signal support?");
        // errno is set by sigaltstack
        return -1;
    }

    DEBUG_MPK("Created new thread with tid = %zu", tid);

    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_initialize_parent(int did, int parent_did) {
    assert_ifdebug(_domain_exists(did));
    assert_ifdebug(_domain_exists(parent_did));
    _pk_domain* new_domain = &pk_data.domains[did];
    new_domain->parent_did = parent_did;
    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_initialize_sysfilter(int did) {
    assert_ifdebug(_domain_exists(did));
    _pk_domain* new_domain = &pk_data.domains[did];

    pthread_mutex_init(&new_domain->syscall_lock, NULL);

    // domain initially allows all syscalls
    for (size_t i = 0; i < NUM_DOMAIN_FILTERS; i++) {
        new_domain->sf_table[i].filter = SYSCALL_ALLOWED;
    }

#ifndef RELEASE
    for (size_t i = 0; i < sizeof(new_domain->padding1); i++)
    {
        new_domain->padding1[i] = (char)i;
        new_domain->padding2[i] = (char)i;
    }
#endif
    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_create_unlocked(unsigned int flags){
    // Attention: pk_trusted_tls might not be fully initialized yet
    // Check for pk_trusted_tls.init before using CURRENT_DID
    DEBUG_MPK("_pk_domain_create_unlocked");
    int ret;

    if (flags & ~(unsigned int)(PK_KEY_SHARED | PK_KEY_INHERIT | PK_KEY_COPY | PK_KEY_OWNER)){
        ERROR("_pk_domain_create_unlocked: Invalid flags");
        errno = EINVAL;
        return DID_INVALID;
    }

    if (flags & (PK_KEY_COPY | PK_KEY_OWNER) &&
        !(flags & PK_KEY_INHERIT)){
        ERROR("_pk_domain_create_unlocked: PK_KEY_COPY | PK_KEY_OWNER are only allowed in combination with PK_KEY_INHERIT");
        errno = EINVAL;
        return DID_INVALID;
    }

    // allocate domain (did)
    int did = PK_DOMAIN_CURRENT;
    for (int d = 0; d < NUM_DOMAINS; d++) {
        if(!pk_data.domains[d].used) {
            did = d;
            break;
        }
    }
    if (PK_DOMAIN_CURRENT == did) {
        ERROR("_pk_domain_create_unlocked could not allocate domain");
        errno = ENOMEM;
        return DID_INVALID;
    }

    // claim domain
    _pk_domain * new_domain = &(pk_data.domains[did]);
    new_domain->used = true;
    new_domain->parent_did = DID_INVALID;

    //before allocating/assigning keys, initialize thread-domain struct
    //because _pk_domain_assign_pkey_unlocked calls read_pkru_current_thread which requires the default-pkru to be set.
    //_pk_get_thread_domain_data_nodidcheck(did);

    // Allocate domain's default key
    vkey_t vkey = _pk_pkey_alloc_unlocked(did, flags & PK_KEY_SHARED, 0);
    if(vkey < 0){
        new_domain->used = false;
        ERROR("_pk_domain_create_unlocked could not allocate vkey");
        // errno is set by _pk_pkey_alloc_unlocked
        goto cleanup1;
    }
    //assert_ifdebug(vkey == KEY_FOR_EXCEPTION_HANDLER || did != DID_FOR_EXCEPTION_HANDLER);
    //~ assert(vkey == KEY_FOR_EXCEPTION_HANDLER || did != DID_FOR_EXCEPTION_HANDLER);
    pkey_t pkey = _vkey_to_pkey(did, vkey); //used for cleanup

//#ifdef SHARED
    // Give read-only access to certain pk data needed for, e.g.:
    // dl_iterate_phdr (c++ exception handling, libc destructors, etc.
    // This needs to access .plt and likewise
    if (rokey_for_exception_handler.vkey != VKEY_INVALID) {
        ret = _pk_domain_assign_pkey_unlocked(DID_FOR_EXCEPTION_HANDLER, did, rokey_for_exception_handler.vkey, PK_KEY_COPY, PKEY_DISABLE_WRITE, false);
        if (0 != ret) {
            ERROR("_pk_domain_create_unlocked could not assign read-only key");
            // errno is set by _pk_domain_assign_pkey_unlocked
            goto cleanup2;
        }
    }
//#endif

    // Do arch-specific domain setup (once we have given the domain all its keys)
    _pk_setup_domain_pkru(did);

    // Inherit default key if requested
    if (flags & PK_KEY_INHERIT) {
        ret = _pk_domain_assign_pkey_unlocked(did, CURRENT_DID, vkey, flags & (PK_KEY_COPY | PK_KEY_OWNER), 0, false);
        if (0 != ret) {
            // errno is set by _pk_domain_assign_pkey_unlocked
            goto cleanup2;
        }
    }

    //Note that creating (and protecting) the stack for each new domain
    //happens per thread (and only on demand).

    return did;

cleanup2:
    assert(/*pkey > 0 &&*/ pkey < PK_NUM_KEYS);
    if (0 != PKEY_FREE(pkey)) {
        WARNING("Unable to free protection key! Ignoring.");
    }
cleanup1:
    memset(new_domain, 0, sizeof(*new_domain));
    return DID_INVALID;
}

//------------------------------------------------------------------------------

bool PK_CODE _untrack_memory(void *addr, size_t len) {
    //DEBUG_MPK("_untrack_memory(%p, %zu)", addr, len);

    assert(((uintptr_t)addr % PAGESIZE) == 0);
    assert((len % PAGESIZE) == 0);

    mprotect_t splittail = { .used = false };
    size_t split_rid = SIZE_MAX;

    // truncate/split potential overlapping ranges
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (!pk_data.ranges[rid].used) { continue; }
        if (_memory_overlaps(addr, len, pk_data.ranges[rid].addr, pk_data.ranges[rid].len)) {
            //DEBUG_MPK("memory overlaps with %p (0x%lx)", pk_data.ranges[rid].addr, pk_data.ranges[rid].len);
            // Distinguish cases of old range (O) and new range (N)
            if (_address_overlaps(pk_data.ranges[rid].addr, addr, len)) {
                // old range-start is within delete range
                if (_address_overlaps((char*)pk_data.ranges[rid].addr+pk_data.ranges[rid].len-1, addr, len)) {
                    //DEBUG_MPK("_untrack_memory: case 1: overlapping range fully covered. Deleting it");
                    // old range-end is within delete range
                    // DDDDDDDDDD
                    //     OOOO
                    // discard old range completely
                    memset(&pk_data.ranges[rid], 0, sizeof(mprotect_t));
                    if(rid == pk_data.ranges_max_used){
                        //find new end
                        size_t highest_rid_used = 0;
                        for (size_t tmp_rid = 0; tmp_rid < NUM_MPROTECT_RANGES; tmp_rid++) {
                            if (pk_data.ranges[tmp_rid].used) {
                                highest_rid_used = tmp_rid;
                            }
                        }
                        pk_data.ranges_max_used = highest_rid_used;
                    }
                } else {
                    // DEBUG_MPK("_untrack_memory: case 2: overlapping range right-overlap. Truncating it");
                    // DEBUG_MPK("Original: %p (0x%zu)", pk_data.ranges[rid].addr, pk_data.ranges[rid].len);
                    // old range-end is outside delete range
                    // DDDDDDDDDD
                    //     OOOOOOOOO
                    // truncate old range
                    //           OOO
                    char* end = (char*)pk_data.ranges[rid].addr + pk_data.ranges[rid].len;
                    pk_data.ranges[rid].addr = (char*)addr + len;
                    assert_ifdebug((char*)end >= (char*)pk_data.ranges[rid].addr);
                    pk_data.ranges[rid].len = (size_t)((char*)end - (char*)pk_data.ranges[rid].addr);
                    assert_ifdebug((pk_data.ranges[rid].len % PAGESIZE) == 0);
                    assert_ifdebug(pk_data.ranges[rid].len > 0);
                    // DEBUG_MPK("Truncated: %p (0x%zu)", pk_data.ranges[rid].addr, pk_data.ranges[rid].len);
                }
            } else {
                // old range-start is outside delete range
                if (_address_overlaps((char*)pk_data.ranges[rid].addr+pk_data.ranges[rid].len-1, addr, len)) {
                    // DEBUG_MPK("_untrack_memory: case 3: overlapping range left-overlap. Truncating it");
                    // DEBUG_MPK("Original: %p (0x%zu)", pk_data.ranges[rid].addr, pk_data.ranges[rid].len);
                    // old range-end is within delete range
                    //     DDDDDDDD
                    // OOOOOOOO
                    // truncate old range
                    // OOOO
                    assert_ifdebug((char*)addr >= (char*)pk_data.ranges[rid].addr);
                    pk_data.ranges[rid].len = (size_t)((char*)addr - (char*)pk_data.ranges[rid].addr);
                    assert_ifdebug((pk_data.ranges[rid].len % PAGESIZE) == 0);
                    assert_ifdebug(pk_data.ranges[rid].len > 0);
                    // DEBUG_MPK("Truncated: %p (0x%zu)", pk_data.ranges[rid].addr, pk_data.ranges[rid].len);
                } else {
                    // DEBUG_MPK("_untrack_memory: case 4: overlapping range covers new. Splitting it");
                    // old range-end is outside delete range
                    //     DDDDDDDD
                    // OOOOOOOOOOOOOOO
                    // we have to split original range into two
                    // OOOO        OOO
                    // for this we need at least 1 free range

                    // search for a free range
                    for (split_rid = 0; split_rid < NUM_MPROTECT_RANGES; split_rid++) {
                        if (!pk_data.ranges[split_rid].used) {
                            break;
                        }
                    }
                    if (split_rid >= NUM_MPROTECT_RANGES) {
                        errno = ENOMEM;
                        ERROR("_untrack_memory has too few ranges available for a split");
                        return false;
                    }
                    // Now do the split
                    // First, truncate beginning
                    // OOOO
                    assert_ifdebug((char*)addr >= (char*)pk_data.ranges[rid].addr);
                    char* tailend = (char*)pk_data.ranges[rid].addr + pk_data.ranges[rid].len;
                    pk_data.ranges[rid].len = (size_t)((char*)addr - (char*)pk_data.ranges[rid].addr);
                    assert_ifdebug((pk_data.ranges[rid].len % PAGESIZE) == 0);
                    assert_ifdebug(pk_data.ranges[rid].len > 0);
                    // Second, store truncated old tail in splittail for later insertion into split_rid
                    // OOOO        OOO
                    splittail.addr = (char*)addr + len;
                    assert_ifdebug((char*)tailend >= (char*)splittail.addr);
                    splittail.len  = (size_t)((char*)tailend - (char*)splittail.addr);
                    assert_ifdebug((splittail.len % PAGESIZE) == 0);
                    assert_ifdebug(((uintptr_t)splittail.addr % PAGESIZE) == 0);
                    splittail.prot        = pk_data.ranges[rid].prot;
                    splittail.vkey        = pk_data.ranges[rid].vkey;
                    splittail.pkey        = pk_data.ranges[rid].pkey;
                    splittail.mmap_fd     = pk_data.ranges[rid].mmap_fd;
                    splittail.mmap_flags  = pk_data.ranges[rid].mmap_flags;
                    splittail.mmap_offset = pk_data.ranges[rid].mmap_offset;
                    splittail.used        = true;
                    if(pk_data.ranges[rid].name){
                        //~ splittail.name = strdup(pk_data.ranges[rid].name);
                    }

                }
            }
        }
    }

    _mrange_update_dir(addr, len, NULL);

    if (splittail.used) {
        // we insert split tail at the end
        assert(split_rid != SIZE_MAX);
        assert(!pk_data.ranges[split_rid].used);
        pk_data.ranges[split_rid] = splittail;
        _mrange_update_dir(splittail.addr, splittail.len, &(pk_data.ranges[split_rid]));
    }
    if(split_rid > pk_data.ranges_max_used){
        pk_data.ranges_max_used = split_rid;
    }
    //_pk_print_debug_info();
#ifdef ADDITIONAL_DEBUG_CHECKS
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (pk_data.ranges[rid].used) {
            assert(!_memory_overlaps(pk_data.ranges[rid].addr, pk_data.ranges[rid].len, addr, len));
        }
    }
#endif // ADDITIONAL_DEBUG_CHECKS

    return true;
}

//------------------------------------------------------------------------------

bool PK_CODE _track_memory(void *addr, size_t len, int prot, vkey_t vkey, pkey_t pkey, bool is_mmap, int mmap_flags, int mmap_fd, off_t mmap_offset) {
    //DEBUG_MPK("_track_memory(%p, %zu, %d, %d, %d)", addr, len, prot, vkey, pkey);

    assert(((uintptr_t)addr % PAGESIZE) == 0);
    assert((len % PAGESIZE) == 0);

    // count free ranges
    int free_rids_required = 2;
    int free_rids = 0;
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (!pk_data.ranges[rid].used) {
            free_rids++;
            if(free_rids >= free_rids_required){
                break;
            }
        }
    }

    if (free_rids < free_rids_required) {
        errno = ENOMEM;
        ERROR("Too few ranges available for a potential split");
        return false;
    }

    if(!is_mmap){
        //recover mmap flags (before they are lost due to untrack_memory)
        mprotect_t * range_old = _get_tracked_memory(addr);
        if(range_old){
            mmap_flags  = range_old->mmap_flags;
            mmap_fd     = range_old->mmap_fd;
            mmap_offset = range_old->mmap_offset;
        }
    }


    // truncate existing memory that overlaps with new range
    if (!_untrack_memory(addr, len)) {
        errno = ENOMEM;
        ERROR("Unable to truncate existing memory");
        return false;
    }

#ifdef ADDITIONAL_DEBUG_CHECKS
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (pk_data.ranges[rid].used) {
            assert(!_memory_overlaps(pk_data.ranges[rid].addr, pk_data.ranges[rid].len, addr, len));
        }
    }
#endif // ADDITIONAL_DEBUG_CHECKS

    // DEBUG_MPK("inserting new range");
    // insert new range
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (!pk_data.ranges[rid].used) {
            pk_data.ranges[rid].addr        = addr;
            pk_data.ranges[rid].len         = len;
            pk_data.ranges[rid].prot        = prot;
            pk_data.ranges[rid].vkey        = vkey;
            pk_data.ranges[rid].pkey        = pkey;
            pk_data.ranges[rid].used        = true;
            pk_data.ranges[rid].name        = NULL;
            pk_data.ranges[rid].mmap_flags  = mmap_flags;
            pk_data.ranges[rid].mmap_fd     = mmap_fd;
            pk_data.ranges[rid].mmap_offset = mmap_offset;
            _mrange_update_dir(addr, len, &(pk_data.ranges[rid]));
            if(rid > pk_data.ranges_max_used){
                pk_data.ranges_max_used = rid;
            }
            return true;
        }
    }
    ERROR("Too few ranges available."
          "We're potentially in an inconsistent state.");
    return false;
}
//------------------------------------------------------------------------------

/**
 * This function must not use CURRENT_DID, as it might not be available yet.
 */
int PK_CODE _pk_pkey_mprotect_unlocked_nodid_check(int did, void *addr, size_t len, int prot, vkey_t vkey, int mmap_flags, int mmap_fd, off_t mmap_offset){
    DEBUG_MPK("_pk_pkey_mprotect_unchecked(%d, addr=%p, len=0x%zx, %d, %d)", did, addr, len, prot, vkey);

    if ((uintptr_t)addr % PAGESIZE || len % PAGESIZE) {
      ERROR("_pk_pkey_mprotect_unlocked: memory range is not page-aligned");
      errno = EINVAL;
      return -1;
    }

    if (!_domain_exists(did)){
        ERROR("_pk_pkey_mprotect_unlocked domain does not exist");
        errno = EINVAL;
        return -1;
    }

    if(PK_DEFAULT_KEY == vkey){
        vkey = _get_default_vkey(did);
        if (PK_DEFAULT_KEY == vkey) {
          ERROR("_pk_pkey_mprotect_unlocked domain has no default vkey");
          errno = EACCES;
          return -1;
        }
    }

    if (!_domain_owns_vkey_nodidcheck(did, vkey)){
        ERROR("_pk_pkey_mprotect_unlocked: domain does not own vkey");
        errno = EACCES;
        return -1;
    }

    pkey_t pkey = _vkey_to_pkey(did, vkey);

    if (!_domain_owns_memory(did, addr, len)) {
        ERROR("_pk_pkey_mprotect_unlocked: domain does not own memory range");
        errno = EACCES;
        return -1;
    }

    int ret = PKEY_MPROTECT(addr, len, prot, pkey);
    if(ret != 0){
        ERROR("_pk_pkey_mprotect_unlocked: mprotect failed");
        perror("pkey_mprotect");
        // errno is set by pkey_mprotect
        return -1;
    }

    if (!_track_memory(addr, len, prot, vkey, pkey, false, mmap_flags, mmap_fd, mmap_offset)) {
        ERROR("_pk_pkey_mprotect_unlocked cannot track more mprotect calls");
        errno = ENOMEM;
        return -1;
    }

    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_pkey_mprotect_unlocked(int did, void *addr, size_t len, int prot, vkey_t vkey, int mmap_flags, int mmap_fd, off_t mmap_offset){
    DEBUG_MPK("_pk_pkey_mprotect_unlocked(%d, addr=%p, len=0x%zx, %d, %d)", did, addr, len, prot, vkey);

    if(!_domain_is_current_or_child(did)){
        ERROR("_pk_pkey_mprotect_unlocked only allowed on current DID or child");
        ERROR("CURRENT_DID = %d", CURRENT_DID);
        errno = EACCES;
        return -1;
    }

    return _pk_pkey_mprotect_unlocked_nodid_check(did, addr, len, prot, vkey, mmap_flags, mmap_fd, mmap_offset);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_pkey_munprotect_unlocked(int did, void *addr, size_t len, int prot) {
    DEBUG_MPK("_pk_pkey_munprotect_unlocked(%d, addr=%p, len=0x%zx, %d)", did, addr, len, prot);

    if ((uintptr_t)addr % PAGESIZE || len % PAGESIZE) {
      ERROR("_pk_pkey_munprotect_unlocked: memory range is not page-aligned");
      errno = EINVAL;
      return -1;
    }

    if (!_domain_owns_memory(did, addr, len)) {
        ERROR("_pk_pkey_munprotect_unlocked: domain does not own memory range");
        errno = EACCES;
        return -1;
    }

    int ret = PKEY_MPROTECT(addr, len, prot, 0);
    if(ret != 0){
        ERROR("_pk_pkey_munprotect_unlocked: mprotect failed");
        perror("pkey_mprotect");
        // errno is set by pkey_mprotect
        return -1;
    }

    if (!_untrack_memory(addr, len)) {
        ERROR("_pk_pkey_munprotect_unlocked cannot untrack");
        errno = ENOMEM;
        return -1;
    }

    return 0;
}
//------------------------------------------------------------------------------

vkey_t PK_CODE _pk_pkey_alloc_unlocked(int did, unsigned int flags, unsigned int access_rights){
    DEBUG_MPK("_pk_pkey_alloc(%d, %d)", flags, access_rights);

    if (flags & ~(unsigned int)(PK_KEY_SHARED) || (access_rights & ~(unsigned int)(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE))) {
        ERROR("_pk_pkey_alloc invalid flags or access rights");
        errno = EINVAL;
        return -1;
    }

    if (!_domain_exists(did)) {
        ERROR("_pk_pkey_alloc domain does not exist");
        errno = EINVAL;
        return -1;
    }

    // find free key slot
    size_t key_id;
    for (key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++) {
        if (!pk_data.domains[did].keys[key_id].used) {
            break;
        }
    }
    if (key_id >= NUM_KEYS_PER_DOMAIN) {
        ERROR("_pk_pkey_alloc could not allocate key slot for domain");
        errno = ENOMEM;
        return -1;
    }

    // check allocation of virtual protection key
    if (pk_vkey_cnt >= VKEY_MAX) {
        ERROR("_pk_pkey_alloc could not allocate vkey");
        errno = ENOSPC;
        return -1;
    }

    int pka = PKEY_ALLOC(flags & ~(unsigned int)PK_KEY_SHARED, access_rights);
    assert_ifdebug(pka != 0); //pkey_alloc returns a negative number on errors, or a positive pkey. pkey 0 is reserved and should never be returned by kernel.
    pkey_t pkey;
    if (pka < 0) {
        // run out of regular protection keys
        if (flags & PK_KEY_SHARED) {
          // Find shared key with lowest shared-counter
          int cnt_min = INT_MAX;
          pkey_t pkey_min = 0;
          for (size_t i = 0; i < PK_NUM_KEYS; i++) {
            if (pk_shared_pkeys[i] > 0 && pk_shared_pkeys[i] < cnt_min) {
              cnt_min = pk_shared_pkeys[i];
              pkey_min = i;
            }
          }
          if (cnt_min >= INT_MAX) {
            ERROR("_pk_pkey_alloc could not allocate shared key");
            errno = ENOSPC;
            return -1;
          }
          if (pk_shared_pkeys[pkey_min] >= INT_MAX) {
            ERROR("_pk_pkey_alloc shared pkey cannot be re-shared");
            errno = ENOSPC;
            return -1;
          }
          pkey = pkey_min;
          pk_shared_pkeys[pkey_min]++;
          DEBUG_MPK("_pk_pkey_alloc reusing shared key %d with counter %d\n", pkey_min, cnt_min);
        } else {
          ERROR("_pk_pkey_alloc could not allocate key");
          // errno is set by pkey_alloc
          return -1;
        }
    } else {
      pkey = pka;
      if (flags & PK_KEY_SHARED) {
        // mark key as shareable by setting its shared-counter to 1
        assert(/*pkey >= 0 &&*/ pkey < PK_NUM_KEYS);
        assert(pk_shared_pkeys[pkey] == 0);
        pk_shared_pkeys[pkey] = 1;
      }
    }

    // allocate virtual protection key
    vkey_t vkey = pk_vkey_cnt++;

    #ifndef RELEASE
    if (!(flags & PK_KEY_SHARED)) {
        for (size_t i = 0; i < NUM_DOMAINS; i++) {
            if(! pk_data.domains[i].used) {
                continue;
            }
            for (size_t j = 0; j < NUM_KEYS_PER_DOMAIN; j++) {
                pk_key_t k = pk_data.domains[i].keys[j];
        
                //key already used by another domain.
                //double allocation
                assert(!(k.used && k.vkey == vkey));
                if (!(flags & PK_KEY_SHARED)) {
                  assert(!(k.used && k.pkey == pkey));
                }
            }
        }
    }
    #endif


    DEBUG_MPK("_pk_pkey_alloc: allocated pkey=%d,vkey=%d\n", pkey, vkey);
    // store key in domain's key slot
    pk_data.domains[did].keys[key_id].vkey  = vkey;
    pk_data.domains[did].keys[key_id].pkey  = pkey;
    pk_data.domains[did].keys[key_id].owner = true;
    pk_data.domains[did].keys[key_id].used  = true;
    pk_data.domains[did].keys[key_id].perm  = access_rights;

    
    return vkey;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_sysfilter_module_load() {
    DEBUG_MPK("Loading sysfilter module");
    sysfilter_pid = getpid();
    sysfilter_fd = open(SYSFILTER_DEVICE_PATH, O_RDONLY);
    if (sysfilter_fd < 0) {
        WARNING("Could not open sysfilter device: %s", SYSFILTER_DEVICE_PATH);
        // errno set by open
        return -1;
    }

    pk_sysfilter_module = true;

    DEBUG_MPK("Apply sysfilter to current PID: %d", getpid());
    if (-1 == ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_PID, getpid())) {
        // errno set by ioctl
        DEBUG_MPK("Apply sysfilter to PID  %d failed", getpid());
        return -1;
    }

    if (-1 == ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_REGISTER_MONITOR, &_pk_syscall_handler)) {
        // errno set by ioctl
        DEBUG_MPK("Could not configure kill-on-violation");
        return -1;
    }

    //~ if (-1 == ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_KILL_ON_VIOLATION, 1)) {
        //~ // errno set by ioctl
        //~ DEBUG_MPK("Could not configure kill-on-violation");
        //~ return -1;
    //~ }

    return 0;
}
//------------------------------------------------------------------------------
    
int PK_CODE _pk_sysfilter_module_unload() {
    if (sysfilter_fd < 0) {
        ERROR("Could not open sysfilter device: %s", SYSFILTER_DEVICE_PATH);
        errno = EACCES;
        return -1;
    }

    if (-1 == ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_PID, 0)) {
        DEBUG_MPK("Unable to disable PID filter. Maybe we're child");
        // errno set by ioctl
        return -1;
    }
    close(sysfilter_fd);
    sysfilter_fd = -1;
    return 0;
}
//------------------------------------------------------------------------------

#ifdef SHARED

/**
 * Copied from RISCV-PK:
 * 
 * The protection flags are in the p_flags section of the program header.
 * But rather annoyingly, they are the reverse of what mmap expects.
 */
int PK_CODE_INLINE _get_prot_phdr_flags(uint32_t p_flags)
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
} domain_t;
//------------------------------------------------------------------------------

typedef struct {
  void* start;
  size_t size;
  int prot;
} protected_t;
//------------------------------------------------------------------------------

const size_t MAX_PROTECTED_RANGES = 128;
protected_t pk_protected_ranges[MAX_PROTECTED_RANGES];
size_t pk_protected_ranges_freeidx = 0;
//------------------------------------------------------------------------------

int PK_CODE _reprotect_phdr(domain_t* domain, struct dl_phdr_info *info, Elf64_Phdr* phdr) {
  uintptr_t start = info->dlpi_addr + phdr->p_vaddr;
  uintptr_t end = start + phdr->p_memsz;
  start = ROUNDDOWN_PAGE(start);
  end = ROUNDUP_PAGE(end);
  // Mprotect with same permissions
  int prot = _get_prot_phdr_flags(phdr->p_flags);
  int ret = _pk_pkey_mprotect_unlocked_nodid_check(domain->did, (void*)start, end - start, prot, domain->vkey, 0,0,0);
  if (-1 == ret) {
        perror("_pk_pkey_mprotect_unlocked_nodid_check failed");
        return -1;
  }
  if (pk_protected_ranges_freeidx >= MAX_PROTECTED_RANGES) {
    WARNING("Ran out of protected ranges. Will not be able to unprotect them upon pk_deinit");
  } else {
    protected_t* p = &pk_protected_ranges[pk_protected_ranges_freeidx];
    p->start = (void*)start;
    p->size = end - start;
    p->prot = prot;
    pk_protected_ranges_freeidx++;
  }
  #ifndef RELEASE
    _pk_name_range((void*)start, end - start, sprintf_and_malloc("Dom %d: phdr", domain->did));
  #endif
  return 0;
}
//------------------------------------------------------------------------------
int PK_CODE _phdr_pointer_in_module(struct dl_phdr_info *info, uintptr_t ptr) {
    for (int j = 0; j < info->dlpi_phnum; j++) {
        Elf64_Phdr phdr = info->dlpi_phdr[j];
        if (phdr.p_type == PT_LOAD) {
            uintptr_t start = info->dlpi_addr + phdr.p_vaddr;
            uintptr_t end = start + phdr.p_memsz;
            if (IN_RANGE(start, ptr, end)){
                return 1;
            }
        }
    }
    return 0;
}
//------------------------------------------------------------------------------
int PK_CODE _phdr_is_ignored_module(struct dl_phdr_info *info) {
    int ret = 0;
    ret |= _phdr_pointer_in_module(info, (uintptr_t)(&pk_init));
    ret |= _phdr_pointer_in_module(info, (uintptr_t)(0x402000)); // test0 etc
    ret |= _phdr_pointer_in_module(info, (uintptr_t)(&pkey_set));
    return ret;
}
//------------------------------------------------------------------------------
int PK_CODE _phdr_is_trusted_module(struct dl_phdr_info *info) {
    int ret = 0;
    ret |= _phdr_pointer_in_module(info, (uintptr_t)(&_phdr_is_trusted_module));
    return ret;
}
//------------------------------------------------------------------------------
int PK_CODE _pk_phdr_scan_binary(struct dl_phdr_info *info, size_t size, void *data) {
    if(!pk_data.binary_scanning){
        return 0;
    }
    DEBUG_MPK("Module %s (%d segments)", info->dlpi_name, info->dlpi_phnum);

    //~ if(_phdr_is_trusted_module(info)){
        //~ DEBUG_MPK("Skipping trusted module");
        //~ return 0;
    //~ }
    if(_phdr_is_ignored_module(info)){
        DEBUG_MPK("Skipping trusted module");
        return 0;
    }
    if(strcmp(info->dlpi_name, "/lib64/ld-linux-x86-64.so.2") == 0){
        DEBUG_MPK("Skipping trusted module");
        return 0;
    }

    int ret = 0;
    for (int j = 0; j < info->dlpi_phnum; j++) {
        Elf64_Phdr phdr = info->dlpi_phdr[j];
        if (!(phdr.p_flags & PF_X)) {
            //skipping
            continue;
        }
        DEBUG_MPK("phdr %2d: address=%10p (0x%010lx) [flags 0x%x %c%c%c] type=%d", 
            j, (void *) (info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz, 
            phdr.p_flags, 
            phdr.p_flags & PF_R ? 'R' : '-',
            phdr.p_flags & PF_W ? 'W' : '-',
            phdr.p_flags & PF_X ? 'X' : '-',
            phdr.p_type
        );

        //DEBUG_MPK("Scanning executable segment");
        uintptr_t start = info->dlpi_addr + phdr.p_vaddr;
        uintptr_t size = phdr.p_memsz;
        start = ROUNDDOWN_PAGE(start);
        size = ROUNDUP_PAGE(size);

        ret |= _pk_scan_memory_incl_pitfalls((char*)start, size);
    }
    return ret;
}
//------------------------------------------------------------------------------


int PK_CODE _pk_selfprotect_phdr(struct dl_phdr_info *info, size_t size, void *data)
{
    int j;
    int ret;
    domain_t* domain = (domain_t*)data;

    // We grant global read-only access to all non-writable PT_LOAD sections
    assert(rokey_for_exception_handler.vkey != VKEY_INVALID);
    domain_t rokey = {
      .did = DID_INVALID,
      .vkey = rokey_for_exception_handler.vkey,
    };

    if (domain) {
        DEBUG_MPK("_pk_selfprotect_phdr(%d, %d)", domain->did, domain->vkey);
        rokey.did = domain->did;
    } else {
        DEBUG_MPK("_pk_selfprotect_phdr()");
    }
    DEBUG_MPK("Module %s (%d segments)", info->dlpi_name, info->dlpi_phnum);

    // Search for module that contains our code
    if(0 == _phdr_is_trusted_module(info)){
        // We're in the wrong module
        //DEBUG_MPK("Skipping");
        return 0;
    }

    // Re-protect all PT_LOAD (+ GNU_RELRO) segments with did/vkey
    for (j = 0; j < info->dlpi_phnum; j++) {
        Elf64_Phdr phdr = info->dlpi_phdr[j];
        if (phdr.p_type == PT_LOAD) {
            DEBUG_MPK("Reprotecting PT_LOAD   %2d: address=%10p (0x%010lx) [flags 0x%x]", j, (void *) (info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz, phdr.p_flags);
            if (domain) {
                if (phdr.p_flags & PF_W) {
                    // make whole PK_DATA read-only accessible
                    //ret = _reprotect_phdr(domain, info, &phdr);
                    ret = _reprotect_phdr(&rokey, info, &phdr);
                } else {
                    ret = _reprotect_phdr(&rokey, info, &phdr);
                }
                if (-1 == ret) {
                    // errno set by _reprotect_phdr
                    return -1;
                }
            } else {
                WARNING("not implemented");
            }
        } else if (phdr.p_type == PT_GNU_RELRO) {
            DEBUG_MPK("Reprotecting GNU_RELRO %2d [%d]: address=%10p (0x%010lx) [flags 0x%x]", j, phdr.p_type, (void *) (info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz, phdr.p_flags);
            if (domain) {
                assert(!(phdr.p_flags & PF_W)); // writable RELRO does not make sense
                ret = _reprotect_phdr(&rokey, info, &phdr);
                if (-1 == ret) {
                    // errno set by _reprotect_phdr
                    return -1;
                }
            } else {
                WARNING("not implemented");
            }
        } else if (phdr.p_type == PT_TLS) {
            DEBUG_MPK("Ignoring     PT_TLS    %2d [%d]: address=%10p (0x%010lx) [flags 0x%x]", j, phdr.p_type, (void *) (info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz, phdr.p_flags);
        } else {
            DEBUG_MPK("Ignoring header        %2d [%d]: address=%10p (0x%010lx) [flags 0x%x]", j, phdr.p_type, (void *) (info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz, phdr.p_flags);
        }
    }
    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_selfprotect(int did, vkey_t vkey) {
  DEBUG_MPK("Selfprotecting PK\n");
  domain_t domain = {
    .did = did,
    .vkey = vkey,
  };
  //print_maps();
  int ret = dl_iterate_phdr(_pk_selfprotect_phdr, &domain);
  ret |= dl_iterate_phdr(_pk_phdr_scan_binary, NULL);
  //print_maps();
  return ret;
}
//------------------------------------------------------------------------------
int PK_CODE _pk_selfunprotect() {

  
  //print_maps();
  DEBUG_MPK("Unprotecting PK in reverse order\n"); // such that RELRO is also undone
  for (size_t i = pk_protected_ranges_freeidx; i > 0; i--) {
    protected_t* p = &pk_protected_ranges[i-1];
    int ret = _pk_pkey_munprotect_unlocked(did_for_exception_handler, p->start, p->size, p->prot);
    if (-1 == ret) {
          perror("_pk_unprotect failed");
          return -1;
    }
  }
  //print_maps();

  return 0;
}
//------------------------------------------------------------------------------

#endif // SHARED

char* PK_DATA pk_args_lower = NULL;
char* PK_DATA pk_args_upper = NULL;

  __attribute__((constructor(101)))
// constructor gets main arguments
void _pk_store_args_pointer(int argc, char** argv, char** env) {
    if(pk_args_lower){
        ERROR_FAIL("constructor called twice");
        return;
    }
    pk_args_lower = argv[0];
    pk_args_upper = argv[0];
    for (int i = 0; i < argc; i++) {
        //~ printf("argc[%d]: %p = %s\n", i, argv[i], argv[i]);
        if (argv[i] < pk_args_lower) {
            pk_args_lower = argv[i];
        }
        if (argv[i] > pk_args_upper) {
            pk_args_upper = argv[i];
        }
    }
    char** e = env;
    while(*e) {
        //~ printf("env: %p = %s\n", *e, *e);
        if (*e < pk_args_lower) {
            pk_args_lower = *e;
        }
        if (*e > pk_args_upper) {
            pk_args_upper = *e;
        }
        e++;
    }
    // Advance pk_args_upper pointer by size of last string argument
    pk_args_upper += strlen(pk_args_upper) + 1;

    // normalize to page boundary
    pk_args_lower = (void*)ROUNDDOWN_PAGE(pk_args_lower);
    pk_args_upper = (void*)ROUNDUP_PAGE(pk_args_upper);
    DEBUG_MPK("Arguments/environment lie in range %p-%p\n", pk_args_lower, pk_args_upper);
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Public API functions
//------------------------------------------------------------------------------

int PK_CODE _pk_deinit(){
    int ret = 0;
    DEBUG_MPK("_pk_deinit");

#ifdef __x86_64__
    if (pk_sysfilter_module && -1 == _pk_sysfilter_module_unload()) {
      // errno set by _pk_unload_sysfilter_module
      ret |= -1;
    }
#endif
    // RISC-V uses hardware syscall delegation, so no need for sysfilter module

    #ifdef SHARED
    if (-1 == _pk_selfunprotect()) {
      // errno set by _pk_selfunprotect
      ERROR("_pk_deinit: unable to unprotect pk memory");
      ret |= -1;
    }
    #endif // SHARED


#ifdef TIMING
    //save stats file
    FILE* f = fopen("results/pk_stats.csv", "w");
    if (!f) {
        ERROR("Could not open stats file");
        // errno set by fopen
        ret |= -1;
    } else {
        FPRINTF(f, "pk_exception_counter, %zu\n", pk_data.stat_num_exceptions);
        fclose(f);
    }
#endif
    return ret;
}
//------------------------------------------------------------------------------

// This is the only function which is API visible for initialization, and
// part of protected PK_CODE
int PK_CODE _pk_init(int flags, void* arg1, void* arg2){
    DEBUG_MPK("_pk_init(%d, %p, %p)", flags, arg1, arg2);
    int ret = 0;

    //setbuf(stdout, NULL);
    //dup2(2, STDERR);

    if (_pk_init_lock()) {
      // errno is set by _pk_init_lock
      goto error;
    }

    _pk_acquire_lock();

    if(pk_data.initialized){
        ERROR("_pk_init: PK already initialized");
        errno = EACCES;
        goto error;
    }

#ifdef DL_HOOKING
    if (-1 == _pk_dl_hooking()) {
        ERROR("_pk_init: Unable to hook libc functions");
        errno = EACCES;
        goto error;
    }
#endif // DL_HOOKING

    _init_debug();

    // verify page size
    long int _pagesize = sysconf(_SC_PAGESIZE);
    if (-1 == _pagesize){
        ERROR("_pk_init: sysconf(_SC_PAGESIZE) failed");
        errno = EACCES;
        goto error;
    }
    if (PAGESIZE != _pagesize){
        ERROR("_pk_init: pagesize does not match. It should be %d but it is %ld", PAGESIZE, _pagesize);
        errno = EACCES;
        goto error;
    }

    // Give monitor full PKRU permission
    ENSURE_FULL_PKRU_ACCESS();

    // allocate DID for root domain
    did_root = _pk_domain_create_unlocked(0);
    if (DID_INVALID == did_root){
        // errno set by _pk_domain_create_unlocked
        goto error;
    }
    assert(did_root == DID_FOR_ROOT_DOMAIN);
    //~ assert(_get_default_vkey(did_root) == KEY_FOR_ROOT_DOMAIN);

    // determine stack size for user code
    pk_data.stacksize = _get_default_stack_size();

    // allocate DID for exception handler
    did_for_exception_handler = _pk_domain_create_unlocked(0);
    if (DID_INVALID == did_for_exception_handler){
        goto error;
    }
    assert(did_for_exception_handler == DID_FOR_EXCEPTION_HANDLER);
    assert(_get_default_vkey(did_for_exception_handler) == SYSFILTER_MONITOR_KEY);

    // get trusted TLS offset
    _pk_ttls_offset = (uint64_t)&pk_trusted_tls.backup_user_stack - GET_TLS_POINTER;

    DEBUG_MPK("Allocating ro-key for exception handler");
    vkey_t ro_vkey = _pk_pkey_alloc_unlocked(did_for_exception_handler, 0, 0);
    //rokey_for_exception_handler = _pk_pkey_alloc_unlocked(did_for_exception_handler, 0, 0);
    if (ro_vkey < 0) {
        ERROR("failed to allocate read-only key");
        // errno set by _pk_pkey_alloc_unlocked
        goto error;
    }
    // allocate read-only key for exception handler memory that can be
    // read by all domains but not written/manipulated
    rokey_for_exception_handler = * _domain_get_pk_key_t(did_for_exception_handler, ro_vkey);
    assert_ifdebug(rokey_for_exception_handler.vkey != VKEY_INVALID);

    // Initialize sysfilter for root and exception handler
    if (-1 == _pk_domain_initialize_sysfilter(did_for_exception_handler) ||
        -1 == _pk_domain_initialize_sysfilter(did_root)) {
        ERROR("Initializing sysfilter for root or exception handler failed");
        goto error;
    }

    int did_child = DID_INVALID;
    if (flags & PK_DROP_CHILD) {
        DEBUG_MPK("Creating child domain");
        did_child = _pk_domain_create_unlocked(0);
        if (-1 == did_child){
            goto error;
        }

        void* exception_stack = _pk_setup_thread_exception_stack();
        ret = _pk_init_thread(did_child, exception_stack);
        if(ret != 0){
            ERROR("_pk_init: _pk_init_thread failed");
            // errno set by _pk_init_thread
            goto error;
        }

        // Initialize parent and sysfilter for child domain
        if (-1 == _pk_domain_initialize_parent(did_child, did_root) ||
            -1 == _pk_domain_initialize_sysfilter(did_child)) {
            ERROR("Initializing did_child parent/sysfilter failed");
            goto error;
        }
    } else {
        // Setup exception handler for current thread
        // Before calling _pk_setup_thread_unlocked we must make sure that we are
        // currently in the domain of the user stack that we want to protect
        void* exception_stack = _pk_setup_thread_exception_stack();
        ret = _pk_init_thread(did_root, exception_stack);
        if(ret != 0){
            ERROR("_pk_init: _pk_init_thread failed");
            // errno set by _pk_init_thread
            goto error;
        }
    }

    // initialize architecture
    if (_pk_init_arch()) {
        ERROR("_pk_init: _pk_init_arch failed");
        errno = EACCES;
        goto error;
    }

    // By now, CURRENT_DID needs to be valid
    // On x86, it is initialized in _pk_init_thread
    // On RISC-V, it is initialized in _pk_init_arch
    if (flags & PK_DROP_CHILD) {
        assert_ifdebug(CURRENT_DID == did_child);
    } else {
        assert_ifdebug(CURRENT_DID == DID_FOR_ROOT_DOMAIN);
    }

//#ifdef SHARED

    if (-1 == _pk_domain_assign_pkey_unlocked(DID_FOR_EXCEPTION_HANDLER,
                                              DID_FOR_ROOT_DOMAIN,
                                              rokey_for_exception_handler.vkey,
                                              PK_KEY_COPY,
                                              PKEY_DISABLE_WRITE,
                                              false)) {
        ERROR("failed to assign read-only key to root domain");
        // errno set by _pk_domain_assign_pkey_unlocked
        goto error;
    }
    if (flags & PK_DROP_CHILD) {
        if (-1 == _pk_domain_assign_pkey_unlocked(DID_FOR_EXCEPTION_HANDLER,
                                                  did_child,
                                                  rokey_for_exception_handler.vkey,
                                                  PK_KEY_COPY,
                                                  PKEY_DISABLE_WRITE,
                                                  false)) {
            ERROR("failed to assign read-only key to child domain");
            // errno set by _pk_domain_assign_pkey_unlocked
            goto error;
        }
    }
//#endif // SHARED

    _pk_setup_domain_pkru(did_for_exception_handler);

    if (flags & PK_DROP_CHILD) {
        _pk_setup_domain_pkru(did_root);

        // Load initial pkru config also into the PKRU reg (for RISC-V)
        pkru_config_t config = _pk_setup_domain_pkru(did_child);
        write_pkru_current_thread(did_child, config);
        assert(PKRU_TO_INT(read_pkru_current_thread(did_child)) == PKRU_TO_INT(_pk_create_default_config_arch(did_child)));
        assert(CURRENT_DID == did_child);
        pk_data.domains[did_child].parent_did = did_root;

        if (NULL != arg1) {
            if (-1 == _pk_domain_register_ecall3_unlocked(did_root, -1, arg1, NULL)) {
                ERROR("Unable to register root domain's entry point");
                // errno set by _pk_domain_register_ecall3_unlocked
                goto error;
            }
            if (-1 == _pk_domain_allow_caller2_unlocked(did_root, did_child, (int)((uintptr_t)arg2))) {
                ERROR("Unable to allow child domain call root domain");
                // errno set by _pk_domain_allow_caller2_unlocked
                goto error;
            }
        }
    } else {
        // Load initial pkru config also into the PKRU reg (for RISC-V)
        pkru_config_t config = _pk_setup_domain_pkru(did_root);
        write_pkru_current_thread(did_root, config);
        assert(PKRU_TO_INT(read_pkru_current_thread(did_root)) == PKRU_TO_INT(_pk_create_default_config_arch(did_root)));
        assert(CURRENT_DID == DID_FOR_ROOT_DOMAIN);
    }

    //set binary scanning
    //NOTE: must happen before _pk_selfprotect
    char* binscan = getenv("BINSCAN");
    if (binscan && strcmp(binscan, "1") == 0) {
        WARNING("setting binary scanning");
        _pk_set_binary_scanning_unlocked(1);
    }

    //Notes:
    //PK_CODE must be protected with exception handler default key.
    //PK_DATA must be protected with rokey_for_exception_handler, such that everyone can read domain metadata.
#ifndef SHARED
    vkey_t key_pk_code = PK_DEFAULT_KEY;
    vkey_t key_pk_data = rokey_for_exception_handler.vkey;
    assert_ifdebug(rokey_for_exception_handler.vkey >= 0);

    DEBUG_MPK("protecting pk data");
    size_t pk_data_size = (size_t)((uintptr_t)__stop_pk_data - (uintptr_t)__start_pk_data);
    ret = _pk_pkey_mprotect_unlocked_nodid_check(did_for_exception_handler,
                                                 (void *)__start_pk_data,
                                                 pk_data_size,
                                                 PROT_WRITE | PROT_READ,
                                                 key_pk_data, 
                                                 0,0,0); //TODO mmap flags
    if(ret != 0){
        ERROR("_pk_init: failed to mprotect pk data");
        // errno set by _pk_pkey_mprotect_unlocked_nodid_check
        goto error;
    }

    DEBUG_MPK("protecting pk code");
    size_t pk_code_size = (size_t)((uintptr_t)__stop_pk_code - (uintptr_t)__start_pk_code);
    ret = _pk_pkey_mprotect_unlocked_nodid_check(did_for_exception_handler,
                                                 (void *)__start_pk_code,
                                                 pk_code_size,
                                                 PROT_EXEC | PROT_READ,
                                                 key_pk_code,
                                                 0,0,0); //TODO mmap flags
    if(ret != 0){
        ERROR("_pk_init: failed to mprotect pk code");
        // errno set by _pk_pkey_mprotect_unlocked_nodid_check
        goto error;
    }

    #ifndef RELEASE
        _pk_name_range((void *)__start_pk_data, pk_data_size, "pk_data");
        _pk_name_range((void *)__start_pk_code, pk_code_size, "pk_code");
    #endif

#else // SHARED

    ret = _pk_selfprotect(did_for_exception_handler, PK_DEFAULT_KEY);
    if (ret != 0) {
        ERROR("_pk_init: failed to mprotect pk code/data");
        // errno set by _pk_selfprotect
        goto error;
    }

#endif // SHARED

    DEBUG_MPK("unprotecting argument/environment pages");
    // unprotect argument/environment page(s)
    if (NULL == pk_args_lower || NULL == pk_args_upper) {
        WARNING("_pk_init: could not determine argument/environment pages. Was constructor called?");
    } else {
        assert(pk_args_upper >= pk_args_lower);
        size_t pk_args_size = (uintptr_t)pk_args_upper - (uintptr_t)pk_args_lower;
        /*ret = _pk_pkey_mprotect_unlocked_nodid_check(did_for_exception_handler,
                                                     pk_args_lower,
                                                     pk_args_size,
                                                     PROT_WRITE | PROT_READ,
                                                     rokey_for_exception_handler);*/
        ret = _pk_pkey_munprotect_unlocked(did_for_exception_handler,
                                           pk_args_lower,
                                           pk_args_size,
                                           PROT_WRITE | PROT_READ);
        if(ret != 0){
            WARNING("_pk_init: failed to unprotect argument/environment pages");
        }
#ifndef RELEASE
        _pk_name_range((void *)pk_args_lower, pk_args_size, "argument+environment");
#endif
    }

    // initialize syscall interposition
#ifdef __x86_64__
    if (flags & PK_SYSMODULE) {
        if (_pk_sysfilter_module_load()) {
            ERROR_FAIL("Unable to load syscall filter. Did you load sysfilter.ko?");
        }
    }
#endif // __x86_64__


    pk_data.initialized = 1; // this is for internal use (protected in PK_DATA)

    DEBUG_MPK("_pk_init done");
    _pk_release_lock();
    
    if (flags & PK_DROP_CHILD) {
        return did_child;
    } else {
        return 0;
    }

error:
    DEBUG_MPK("_pk_init error");
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_create(unsigned int flags){
    DEBUG_MPK("_pk_domain_create(0x%x)", flags);
    assert(pk_data.initialized);

    _pk_acquire_lock();
    int did = _pk_domain_create_unlocked(flags);
    if (DID_INVALID == did) {
        ERROR("Failed to create new child domain");
        goto error;
    }

    // Initialize parent and sysfilter for child domain
    if (-1 == _pk_domain_initialize_parent(did, CURRENT_DID) ||
        -1 == _pk_domain_initialize_sysfilter(did)) {
        ERROR("Initializing parent/sysfilter for new domain failed");
        goto error;
    }

    _pk_release_lock();
     return did;
error:
    _pk_release_lock();
    return DID_INVALID;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_free(int did){
    DEBUG_MPK("_pk_domain_free(%d) (current domain = %d)", did, CURRENT_DID);
    assert(pk_data.initialized);

    _pk_acquire_lock();
    if (PK_DOMAIN_CURRENT == did) {
        did = CURRENT_DID;
    }

    if (!_domain_exists(did)
        || CURRENT_DID == did
        || (DID_INVALID != pk_data.domains[did].parent_did && CURRENT_DID != pk_data.domains[did].parent_did)
    ) {
        WARNING("Invalid did");
        errno = EINVAL;
        _pk_release_lock();
        return -1;
    }

    for (size_t other_did = 0; other_did < NUM_DOMAINS; other_did++){
        if (pk_data.domains[other_did].used
            && pk_data.domains[other_did].parent_did == did
        ) {
            WARNING("cannot orphan child domains");
            errno = EINVAL;
            _pk_release_lock();
            return -1;
        }
    }

    //check running threads
    for (size_t i = 0; i < NUM_THREADS; i++){
        _pk_tls * thread = pk_data.threads[i];
        if(THREAD_UNUSED == thread || THREAD_EXITING == thread){
            continue;
        }
        if(thread->init == 0){
            continue;
        }

        if(thread->current_did == did){
            WARNING("Threads still running in this domain");
            ERROR_FAIL("Not implemented");
            errno = EINVAL;
            _pk_release_lock();
            return -1;
        }
        _pk_thread_domain* data = &thread->thread_dom_data[did];

        // Deinit thread-domain data
        _deallocate_user_stack(data);
        _deallocate_filter_mem(data);
    }
    #ifndef RELEASE
    //Print debug info after setting up domains
    _pk_print_debug_info();
    #endif
    //unprotect memory ranges
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (pk_data.ranges[rid].used && _domain_owns_vkey_nodidcheck(did, pk_data.ranges[rid].vkey)) {
            int ret = _pk_pkey_munprotect_unlocked(did_for_exception_handler, pk_data.ranges[rid].addr, pk_data.ranges[rid].len, pk_data.ranges[rid].prot);
            assert(ret == 0);
        }
    }

    // free all registered signal handlers
    for (int signo = 0; signo < MAX_SIGNO; signo++) {
        if (pk_signal_did[signo] == did) {
            DEBUG_MPK("Freeing signal handler %d", signo);
            SIGNAL(signo, SIG_DFL);
            pk_signal_did[signo] = DID_INVALID;
            memset(&pk_signal_action[signo], 0, sizeof(struct sigaction));
        }
    }

    //free keys
    for (size_t key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++) {
        if (pk_data.domains[did].keys[key_id].used &&
            pk_data.domains[did].keys[key_id].owner
        ) {
            vkey_t vkey = pk_data.domains[did].keys[key_id].vkey;
            int ret = _pk_pkey_free2(did, vkey);
            //note that _pk_pkey_free2 already checks if key is unused
            //note that _pk_pkey_free2 also revokes key in other domains
            if(ret != 0){
                ERROR("pkey %d could not be freed", vkey);
            }
        }
    }

    //free private files
    for (size_t i = 0; i < NUM_PRIVATE_FILES; i++) {
        if(pk_data.private_files[i].domain == did){
            free(pk_data.private_files[i].path);
            pk_data.private_files[i].path   = NULL;
            pk_data.private_files[i].domain = 0;
        }
    }

    //wipe all related data structures
    _pk_domain * dom = &(pk_data.domains[did]);
    memset(dom, 0x00, sizeof(_pk_domain));
    //"free" domain
    assert(dom->used == 0);

    _pk_release_lock();
    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_release_child(int did){
    DEBUG_MPK("_pk_domain_release_child(%d)", did);
    assert(pk_data.initialized);

    _pk_acquire_lock();
    if (!_domain_is_child(did)) {
        ERROR("_pk_domain_release_child domain is not child");
        errno = EINVAL;
        goto error;
    }

    pk_data.domains[did].parent_did = pk_data.domains[CURRENT_DID].parent_did;

    _pk_release_lock();
    return 0;
error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

vkey_t PK_CODE _pk_pkey_alloc(unsigned int flags, unsigned int access_rights){
    return _pk_pkey_alloc2(PK_DOMAIN_CURRENT, flags, access_rights);
}
//------------------------------------------------------------------------------

vkey_t PK_CODE _pk_pkey_alloc2(int did, unsigned int flags, unsigned int access_rights){
    DEBUG_MPK("_pk_pkey_alloc2(%d, %d, %d)", did, flags, access_rights);
    assert(pk_data.initialized);
    _pk_acquire_lock();

    vkey_t key = VKEY_INVALID;

    if (PK_DOMAIN_CURRENT == did) {
        did = CURRENT_DID;
    }

    // did must be current domain or child
    if(!_domain_is_current_or_child(did)){
        ERROR("_pk_pkey_alloc: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    key = _pk_pkey_alloc_unlocked(did, flags, access_rights);
    if (-1 == key) {
      ERROR("could not allocate key");
      //errno set by _pk_domain_load_key_unlocked
      goto error;
    }

    int ret = _pk_domain_load_key_unlocked(did, key, PK_SLOT_ANY, 0);
    if (-1 == ret) {
      ERROR("could not load newly assigned key");
      //errno set by _pk_domain_load_key_unlocked
      goto error;
    }

    _pk_release_lock();
    return key;

error:
    if (VKEY_INVALID != key) {
        // try to cleanup key again
        ret = _pk_pkey_free(key);
        if (-1 == ret) {
            WARNING("_pk_pkey_free failed");
        }
    }
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

bool PK_CODE _pk_is_pkey_loaded_in_any_thread(pkey_t pkey) {

    assert_ifdebug(pkey > 0 && pkey < PK_NUM_KEYS);

    for (size_t tid = 0; tid <  NUM_THREADS; tid++) {
        if (THREAD_UNUSED == pk_data.threads[tid] || THREAD_EXITING == pk_data.threads[tid]) {
            continue;
        }
        assert(pk_data.threads[tid]->init);
        for (int did = 0; did <  NUM_DOMAINS; did++) {
            if( pk_data.threads[tid]->thread_dom_data[did].user_stack_base == 0){
                continue;
            }
            pkru_config_t pkru = read_pkru(did, tid);
            if( _pk_is_pkey_loaded_arch(pkey, pkru)){
                DEBUG_MPK("pkey %d is loaded in did %d and thread index %zu.", pkey, did, tid);
                return true;
            }
        }
    }
    return false;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_pkey_free(vkey_t vkey){
    return _pk_pkey_free2(PK_DOMAIN_CURRENT, vkey);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_pkey_free2(int did, vkey_t vkey){
    DEBUG_MPK("_pk_pkey_free_for_domain(%d, %d)", did, vkey);
    assert(pk_data.initialized);
    int ret;

    _pk_acquire_lock();

    if (PK_DOMAIN_CURRENT == did) {
        did = CURRENT_DID;
    }

    if (!_domain_exists(did)) {
        ERROR("domain does not exist");
        errno = EINVAL;
        goto error;
    }

    //WARNING("pk_data.domains[did].parent_did = %d", pk_data.domains[did].parent_did);
    if (CURRENT_DID != DID_FOR_ROOT_DOMAIN && !_domain_is_current_or_child(did)) {
        ERROR("domain must be current or child");
        errno = EINVAL;
        goto error;
    }

    if (!_domain_owns_vkey_nodidcheck(did, vkey)) {
        ERROR("domain %d does not own vkey %d", did, vkey);
        errno = EACCES;
        goto error;
    }

    //unload key
    //not necessary, instead we want to unassign it. this happens below when we revoke the keys
    //NOTE: unload only works if the thread-did is initialized
    if(_thread_domain_initialized(did)){
        ret = _pk_domain_load_key_unlocked(did, vkey, PK_SLOT_NONE, 0);
        if (-1 == ret) {
            ERROR("Unloading of the key failed.");
            //errno set by _pk_domain_load_key_unlocked
            goto error;
        }
    }

    // check that vkey is unused
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (pk_data.ranges[rid].used && pk_data.ranges[rid].vkey == vkey) {
            ERROR("range[%zu] addr %p len %zu (%s) still uses vkey", rid, pk_data.ranges[rid].addr, pk_data.ranges[rid].len, pk_data.ranges[rid].name);
            errno = EPERM;
            _pk_print_debug_info();
            goto error;
        }
    }

    // check that pkey is not loaded
    // If pkey is allocated under more than one virtual key (vkey),
    // this check is omitted, since multiple vkeys
    // could legitimately be loaded under the same pkey
    pkey_t pkey = _vkey_to_pkey(did, vkey);
    assert(/*pkey >= 0 &&*/ pkey < PK_NUM_KEYS);
    if (pk_shared_pkeys[pkey] <= 1) {
        if (_pk_is_pkey_loaded_in_any_thread(pkey)) {

#if 1
            WARNING("pkey %d is loaded. Unload it first", pkey);
#else
            ERROR("pkey is loaded. Unload it first");
            errno = EPERM;
            goto error;
#endif
        }
    }

    if(pk_trusted_tls.syscall_args_key.used && pk_trusted_tls.syscall_args_key.vkey == vkey){
        ERROR("cannot revoke syscall_args_key");
        errno = EPERM;
        goto error;
    }

    // revoke vkey in all domains
    for (size_t other_did = 0; other_did < NUM_DOMAINS; other_did++) {
        if (pk_data.domains[other_did].used) {
            _pk_domain * domain = &pk_data.domains[other_did];
            for (size_t key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++) {
                if (domain->keys[key_id].used && domain->keys[key_id].vkey == vkey) {
                    domain->keys[key_id].used = false;
                    DEBUG_MPK("revoked domain[%zu].keys[%zu]\n", other_did, key_id);
                }
            }
        }
    }

    if (pk_shared_pkeys[pkey] >= 1) {
      // decrement sharing count down to zero
      pk_shared_pkeys[pkey]--;
      ret = 0;
    } else {
      // free pkey in the kernel
      ret = PKEY_FREE(pkey);
    }

    _pk_release_lock();
    return ret;

error:
    //_pk_print_debug_info();
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_assign_pkey_unlocked(int source_did, int target_did, vkey_t vkey, int flags, unsigned int access_rights, bool load_key){
    DEBUG_MPK("_pk_domain_assign_pkey_unlocked(%d, %d, %d, %d, %u, %d)", source_did, target_did, vkey, flags, access_rights, load_key);

    if (!_domain_exists(source_did)) {
        ERROR("_pk_domain_assign_pkey source domain does not exist");
        errno = EINVAL;
        goto error;
    }

    if (!_domain_exists(target_did)) {
        ERROR("_pk_domain_assign_pkey target domain does not exist");
        errno = EINVAL;
        goto error;
    }

    _pk_domain* current = &pk_data.domains[source_did];
    int key_id = _domain_get_vkey_id(source_did, vkey);

    if (-1 == key_id) {
        ERROR("_pk_domain_assign_pkey domain does not have vkey");
        errno = EACCES;
        goto error;
    }
    pkey_t pkey = _vkey_to_pkey(source_did, vkey);

    if (flags & ~(PK_KEY_OWNER | PK_KEY_COPY)) {
        ERROR("_pk_domain_assign_pkey invalid flags");
        errno = EINVAL;
        goto error;
    }

    bool owner_key = (flags & PK_KEY_OWNER);
    if (owner_key && !current->keys[key_id].owner) {
        ERROR("_pk_domain_assign_pkey domain does not own vkey");
        errno = EACCES;
        goto error;
    }

    bool copy_key       = (flags & PK_KEY_COPY);

    if (access_rights & ~(unsigned int)(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE)) {
        ERROR("_pk_domain_assign_pkey invalid access_rights");
        errno = EINVAL;
        goto error;
    }

    unsigned int current_perm = current->keys[key_id].perm;

    // determine target key slot to use
    size_t target_key_id;
    if (target_did == source_did) {
        // in case we assign the vkey to ourselves, use the original key_id
        target_key_id = (size_t)key_id;
    } else {
        // allocate a new key_id
        for (target_key_id = 0; target_key_id < NUM_KEYS_PER_DOMAIN; target_key_id++) {
            if (!pk_data.domains[target_did].keys[target_key_id].used) {
                break;
            }
        }
        if (target_key_id >= NUM_KEYS_PER_DOMAIN) {
            ERROR("_pk_domain_assign_pkey could not allocate key slot for domain");
            errno = ENOMEM;
            goto error;
        }
    }

    // invalidate original key
    if (!copy_key) {
        current->keys[key_id].used = false;
    }

    // store new key in domain's key slot
    pk_data.domains[target_did].keys[target_key_id].vkey  = vkey;
    pk_data.domains[target_did].keys[target_key_id].pkey  = pkey;
    pk_data.domains[target_did].keys[target_key_id].owner = owner_key;
    pk_data.domains[target_did].keys[target_key_id].perm  = current_perm | access_rights;
    pk_data.domains[target_did].keys[target_key_id].used  = true;

    // load key for target domain
    if(load_key){
        int ret = _pk_domain_load_key_unlocked(target_did, vkey, PK_SLOT_ANY, 0);
        if (-1 == ret) {
          ERROR("_pk_domain_assign_pkey could not load newly assigned key");
          //errno set by _pk_domain_load_key_unlocked
          goto error;
        }
    }
    return 0;

error:
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_assign_pkey(int did, vkey_t vkey, int flags, unsigned int access_rights){
    DEBUG_MPK("_pk_domain_assign_pkey(%d, %d, %d, %u)", did, vkey, flags, access_rights);
    assert(pk_data.initialized);

    _pk_acquire_lock();
    if (PK_DOMAIN_CURRENT == did) {
        did = CURRENT_DID;
    }

    int ret = _pk_domain_assign_pkey_unlocked(CURRENT_DID, did, vkey, flags, access_rights, true);

    _pk_release_lock();

    return ret;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_default_key(int did){
    DEBUG_MPK("_pk_domain_default_key(%d)", did);
    assert(pk_data.initialized);

    vkey_t vkey = VKEY_INVALID;
    _pk_acquire_lock();
    if (PK_DOMAIN_CURRENT == did) {
        did = CURRENT_DID;
    }

    if(!_domain_is_current_or_child(did)){
        ERROR("_pk_domain_default_key: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    vkey = _get_default_vkey(did);
    if (VKEY_INVALID == vkey) {
        ERROR("_pk_domain_default_key: could not retrieve default vkey");
        errno = EACCES;
        goto error;
    }

    _pk_release_lock();
    return vkey;

error:
    _pk_release_lock();
    return VKEY_INVALID;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_pkey_mprotect(void *addr, size_t len, int prot, vkey_t vkey){
    DEBUG_MPK("_pk_pkey_mprotect(%p, %zu, %d, %d)", addr, len, prot, vkey);
    return _pk_pkey_mprotect2(PK_DOMAIN_CURRENT, addr, len, prot, vkey);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_pkey_mprotect2(int did, void *addr, size_t len, int prot, vkey_t vkey){
    DEBUG_MPK("_pk_pkey_mprotect2(%d, %p, %zu, %d, %d)", did, addr, len, prot, vkey);
    assert(pk_data.initialized);

    _pk_acquire_lock();
    if (PK_DOMAIN_CURRENT == did) {
      did = CURRENT_DID;
    }
    int ret = _pk_pkey_mprotect_unlocked(did, addr, len, prot, vkey, 0, 0, 0);

    //print_maps();
    //_pk_print_debug_info();

    _pk_release_lock();

    return ret;
}
//------------------------------------------------------------------------------

void PK_CODE _register_fd_for_monitor(int fd){
    if (fd < 0 || fd > NUM_FDS) {
        return;
    }
    sf_data.fd_domain_mapping[fd] = did_for_exception_handler;
}
//------------------------------------------------------------------------------

void PK_CODE _unregister_fd_for_monitor(int fd){
    if (fd < 0 || fd > NUM_FDS) {
        return;
    }
    //assert(sf_data.fd_domain_mapping[fd] == did_for_exception_handler);
    sf_data.fd_domain_mapping[fd] = FD_DOMAIN_NONE_OR_CLOSED;
}
//------------------------------------------------------------------------------

void* PK_CODE _pk_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  return _pk_mmap2(PK_DOMAIN_CURRENT, addr, length, prot, flags, fd, offset);
}
//------------------------------------------------------------------------------

void* PK_CODE _pk_mmap2(int did, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  DEBUG_MPK("_pk_mmap2(%d, %p, %zu, %d, %d, %d, %ld)", did, addr, length, prot, flags, fd, offset);
  return _pk_mmap_internal(did, PK_DEFAULT_KEY, addr, length, prot, flags, fd, offset);
}
//------------------------------------------------------------------------------

void* PK_CODE _pk_mmap3(vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  DEBUG_MPK("_pk_mmap3(%d, %p, %zu, %d, %d, %d, %ld)", vkey, addr, length, prot, flags, fd, offset);
  return _pk_mmap_internal(PK_DOMAIN_CURRENT, vkey, addr, length, prot, flags, fd, offset);
}
//------------------------------------------------------------------------------

void* PK_CODE _pk_mmap_internal(int did, vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd_original, off_t offset) {
    DEBUG_MPK("_pk_mmap_internal(%d, %d, %p, %zu, %d, %d, %d, %ld)", did, vkey, addr, length, prot, flags, fd_original, offset);
    assert(pk_data.initialized);

    _pk_acquire_lock();

    void* mem = MAP_FAILED;
    int fd_dupped = -1;

    if (PK_DOMAIN_CURRENT == did) {
        did = CURRENT_DID;
    }

    //Note: this check must happen here, since API functions (e.g., from preloading) can bypass sysfilters
    if(!_fd_accessible_by_domain(did, fd_original)){
        errno = EACCES;
        goto error;
    }

    if(! (flags & MAP_ANONYMOUS) && fd_original >= 0){ //mapping is file-backed
        fd_dupped = dup(fd_original);
        if(fd_dupped == -1){
            ERROR("dup failed");
            //errno is set by dup
            goto error;
        }
        _register_fd_for_monitor(fd_dupped);
    }

    // did must be current domain or child
    if(!_domain_is_current_or_child(did)){
        ERROR("only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    length = ROUNDUP_PAGE(length); // pad to page size
    
    if ((uintptr_t)addr % PAGESIZE || length % PAGESIZE) {
        ERROR("memory range is not page-aligned");
        errno = EINVAL;
        goto error;
    }

    if(pk_data.binary_scanning){
        if(prot & PROT_EXEC){
            if(prot & PROT_WRITE){
                ERROR("Executable mapping cannot be writable");
                goto error;
            }
            if((flags & MAP_SHARED)){
                ERROR("Executable mapping cannot be shared memory"); //since other process might have it mapped as writeable
                goto error;
            }
            if(! (flags & MAP_ANONYMOUS)){ //mapping is file-backed
                DEBUG_MPK("! (flags & MAP_ANONYMOUS)");
                //underlying file must not be writable by (other processes of) this user.

                char path_resolved[PATH_MAX];
                if(0 != _fd_path(fd_dupped, path_resolved)){
                    ERROR("_fd_path(%d) failed", fd_dupped);
                    goto error;
                }

                int fd_write = open(path_resolved, O_WRONLY);
                close(fd_write);
                if(fd_write != -1){
                    //file is writable.
                    ERROR("Executable mapping cannot be backed by writable file: %s", path_resolved);
                    goto error;
                }

                DEBUG_MPK("executable mapping is backed by read-only file: %s", path_resolved);

                //map binary as read-only, not executable
                mem = MMAP(addr, length, prot & ~PROT_EXEC, flags, fd_dupped, offset);
                if (MAP_FAILED == mem) {
                    ERROR("failed to map memory");
                    // errno is set by mmap
                    goto error;
                }
                //scan binary
                if(_pk_scan_memory_incl_pitfalls(mem, length)){
                    errno = EACCES;
                    goto error;
                    //NOTE: error unmaps mem for us
                }else{
                    DEBUG_MPK("memory does not contain WRPKRU/XRSTOR");
                }
            }
        }
    }

    if (MAP_FAILED == mem) {
        mem = MMAP(addr, length, prot, flags, fd_dupped, offset);
        if (MAP_FAILED == mem) {
            ERROR("failed to map memory");
            // errno is set by mmap
            goto error;
        }
    }else{
        //memory is already mapped but maybe with wrong permissions
        if (-1 == MPROTECT(mem, length, prot)) {
            ERROR("failed to mprotect");
            // errno is set by mprotect
            goto error;
        }
    }
    DEBUG_MPK("successfully mmaped range [%p, %p]", mem, (void *)((uintptr_t)mem + length));

    // set protection key
    // this also tracks memory
    int ret = _pk_pkey_mprotect_unlocked_nodid_check(did, mem, length, prot, vkey, flags, fd_dupped, offset);
    if (-1 == ret) {
        ERROR("failed to set protection key");
        // errno is set by _pk_pkey_mprotect_unlocked
        goto error;
    }

    _pk_release_lock();
    return mem;

error:
    if (MAP_FAILED != mem) {
        ret = MUNMAP(mem, length);
        if (ret) {
            //errno set by munmap
            ERROR("Unable to unmap memory. We have a memory leak");
        }
    }
    if (-1 != fd_dupped) {
        ret = close(fd_dupped);
        if (ret) {
            //errno is set by close
            ERROR("Unable to close dupped fd.");
        }
    }
    _pk_release_lock();
    return MAP_FAILED;
}
//------------------------------------------------------------------------------

void* PK_CODE _pk_mremap(void *old_address, size_t old_size,
                         size_t new_size, int flags, void *new_address) {
    return _pk_mremap_internal(PK_DOMAIN_CURRENT, old_address, old_size, new_size, flags, new_address);
}
//------------------------------------------------------------------------------

void* PK_CODE _pk_mremap2(int did, void *old_address, size_t old_size,
                          size_t new_size, int flags, void *new_address) {
    return _pk_mremap_internal(did, old_address, old_size, new_size, flags, new_address);
}
//------------------------------------------------------------------------------

void* PK_CODE _pk_mremap_internal(int did, void *old_address, size_t old_size,
                                  size_t new_size, int flags, void *new_address) {
    DEBUG_MPK("_pk_mremap_internal(%d, %p, %zu, %zu %d, %p)", did, old_address, old_size, new_size, flags, new_address);
    assert(pk_data.initialized);

    _pk_acquire_lock();

    //print_maps();

    void* mem = MAP_FAILED;

    if (PK_DOMAIN_CURRENT == did) {
        did = CURRENT_DID;
    }

    // did must be current domain or child
    if(!_domain_is_current_or_child(did)){
        ERROR("_pk_mremap_internal: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    if ((uintptr_t)old_address % PAGESIZE || old_size % PAGESIZE) {
        ERROR("_pk_mremap_internal: memory range is not page-aligned");
        errno = EINVAL;
        goto error;
    }

    // old_size might be 0
    if (!_domain_owns_memory(did, old_address, old_size == 0 ? 1 : old_size)) {
        ERROR("_pk_mremap_internal: domain does not own old memory range");
        errno = EACCES;
        goto error;
    }
    mprotect_t* range = _get_tracked_memory(old_address);
    assert(range != NULL);
    if(old_size){
        assert(range == _get_tracked_memory(old_address + (old_size - 1)));
        //otherwise we need to deal with all affected ranges
    }

    if (flags & MREMAP_FIXED) {
        if (!_domain_owns_memory(did, new_address, new_size)) {
            ERROR("_pk_mremap_internal: domain does not own new memory range");
            errno = EACCES;
            goto error;
        }
    }

    //remove executable flag before moving/scanning
    if(pk_data.binary_scanning && (range->prot & PROT_EXEC)){
        if (-1 == MPROTECT(old_address, old_size, range->prot & ~PROT_EXEC)) {
            ERROR("failed to mprotect");
            // errno is set by mprotect
            goto error;
        }
    }

    mem = MREMAP(old_address, old_size, new_size, flags, new_address);
    if (MAP_FAILED == mem) {
        ERROR("_pk_mremap_internal: failed to remap memory");
        // errno is set by mremap
        goto error;
    }

    if(pk_data.binary_scanning && (range->prot & PROT_EXEC)){
        if(_pk_scan_memory_incl_pitfalls(mem, new_size)){
            errno = EACCES;
            goto error;
        }

        if (-1 == MPROTECT(old_address, old_size, range->prot)) {
            ERROR("failed to mprotect");
            // errno is set by mprotect
            goto error;
        }
    }

    // untrack old memory
    int prot          = range->prot;
    int vkey          = range->vkey;
    int mmap_flags    = range->mmap_flags;
    int mmap_fd       = range->mmap_fd;
    off_t mmap_offset = range->mmap_offset;
    range = NULL; //to avoid accidentally reading the seeon-to-be invalid struct
    if(!_untrack_memory(old_address, old_size)) {
        ERROR_FAIL("_pk_mremap_internal: failed to untrack old memory! We're in an inconsistent state");
    }

    // we take the protection key / rwx from the start of the old memory range
    // and apply it to the new memory range
    int ret = _pk_pkey_mprotect_unlocked_nodid_check(did, mem, new_size, prot, vkey, mmap_flags, mmap_fd, mmap_offset);
    if (-1 == ret) {
        ERROR("_pk_mremap_internal: failed to set protection key");
        // errno is set by _pk_pkey_mprotect_unlocked_nodid_check
        goto error;
    }

    _pk_release_lock();
    return mem;

error:
    _pk_release_lock();
    return MAP_FAILED;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_madvise(void* addr, size_t len, int advice){
    return _pk_madvise2(PK_DOMAIN_CURRENT, addr, len, advice);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_madvise2(int did, void* addr, size_t len, int advice){
    DEBUG_MPK("_pk_madvise2(%d, %p, %zu, %d)", did, addr, len, advice);
    assert(pk_data.initialized);
    _pk_acquire_lock();

    if (PK_DOMAIN_CURRENT == did) {
      did = CURRENT_DID;
    }

    // did must be current domain or child
    if(!_domain_is_current_or_child(did)){
        ERROR("only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    if (!_domain_owns_memory(did, addr, len)) {
        ERROR("domain does not own memory range");
        _pk_print_debug_info2(addr, len);
        errno = EINVAL; //EACCES;
        goto error;
    }

    int ret = MADVISE(addr, len, advice);

    _pk_release_lock();
    return ret;
error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_munmap(void* addr, size_t len){
    return _pk_munmap2(PK_DOMAIN_CURRENT, addr, len);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_munmap2(int did, void* addr, size_t len){
    DEBUG_MPK("_pk_munmap(%d, %p, %zu)",did, addr, len);
    assert(pk_data.initialized);

    _pk_acquire_lock();

    if (PK_DOMAIN_CURRENT == did) {
      did = CURRENT_DID;
    }

    // did must be current domain or child
    if(!_domain_is_current_or_child(did)){
        ERROR("_pk_munmap: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    len = ROUNDUP_PAGE(len); // pad to page size

    if ((uintptr_t)addr % PAGESIZE || len % PAGESIZE) {
        ERROR("_pk_munmap: memory range is not page-aligned");
        errno = EINVAL;
        goto error;
    }

    if (!_domain_owns_memory(did, addr, len)) {
        ERROR("_pk_munmap: domain does not own memory range");
        _pk_print_debug_info2(addr, len);
        errno = EACCES;
        goto error;
    }

    //close fd which we have duplicated in mmap
    mprotect_t* mrange = _get_tracked_memory(addr);
    if(mrange && mrange->mmap_fd > 0){
        int ret = close(mrange->mmap_fd);
        if(ret == -1){
            ERROR("close(%d) failed", mrange->mmap_fd);
            char path[4096] = {0,};
            _fd_path(mrange->mmap_fd, path);
            ERROR("FD %d: %s", mrange->mmap_fd, path);
            perror("");
            //errno is set by close
            goto error;
        }
        _unregister_fd_for_monitor(mrange->mmap_fd);
    }

    if (!_untrack_memory(addr, len)) {
        ERROR("_pk_munmap cannot untrack memory range");
        errno = ENOMEM;
        goto error;
    }

    int ret = MUNMAP(addr, len);
    if (ret) {
        ERROR("_pk_munmap unable to unmap memory");
        // errno is set by munmap
        goto error;
    }

    _pk_release_lock();
    return 0;

error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

//returns 0 on success
int PK_CODE _pk_scan_memory_incl_pitfalls(void *addr, size_t len) {
    DEBUG_MPK("_pk_scan_memory_incl_pitfalls(%p, %zu)", addr, len);
    int ret = 0;
    unsigned long long pos = -1;

    //find actual addr+len to scan:
    size_t max_offset = (INST_LEN_WRPKRU_AND_XRSTOR-1);
    mprotect_t * range_before = _get_tracked_memory(addr - max_offset);
    mprotect_t * range_after  = _get_tracked_memory(addr + len - max_offset);

    if(range_before && range_before->used && range_before->prot & PROT_READ){
        addr -= max_offset;
        len  += max_offset;
        DEBUG_MPK("Extending scanned area to %p with length %zu", addr, len);
    }
    if(range_after && range_after->used && range_after->prot & PROT_READ){
        len  += max_offset;
        DEBUG_MPK("Extending scanned area to %p with length %zu", addr, len);
    }

    pos = _erim_scanMemForWRPKRUXRSTOR(addr, len);
    if(pos != -1){
        DEBUG_MPK(COLOR_RED "Memory %p: found WRPKRU/XRSTOR at pos 0x%llx", addr, pos);
        ret = 1;
    }else{
        DEBUG_MPK("Memory %p: does not contain WRPKRU/XRSTOR", addr);
    }

    return ret;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_mprotect(void *addr, size_t len, int prot) {
    return _pk_mprotect2(PK_DOMAIN_CURRENT, addr, len, prot);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_mprotect2(int did, void *addr, size_t len, int prot) {
    DEBUG_MPK("_pk_mprotect(%d, %p, %zu, %d)",did, addr, len, prot);
    assert(pk_data.initialized);

    _pk_acquire_lock();

    if (PK_DOMAIN_CURRENT == did) {
      did = CURRENT_DID;
    }

    // did must be current domain or child
    if(!_domain_is_current_or_child(did)){
        ERROR("_pk_mprotect: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    if ((uintptr_t)addr % PAGESIZE || len % PAGESIZE) {
        ERROR("_pk_mprotect: memory range is not page-aligned");
        errno = EINVAL;
        goto error;
    }

    //_pk_print_debug_info();
    if (!_domain_owns_memory(did, addr, len)) {
            //_pk_print_debug_info();

        ERROR("_pk_mprotect: domain does not own memory range");
        errno = EACCES;
        goto error;
    }

    if(pk_data.binary_scanning && (prot & PROT_EXEC)){
        if(prot & PROT_WRITE){
            ERROR("Executable mapping cannot be writable");
            goto error;
        }

        //scan binary
        if(_pk_scan_memory_incl_pitfalls(addr, len)){
            errno = EACCES;
            goto error;
            //NOTE: error unmaps mem for us
        }
    }

    int ret = MPROTECT(addr, len, prot);
    if (-1 == ret) {
        ERROR("_pk_mprotect: failed to mprotect");
        // errno is set by mprotect
        goto error;
    }

    // Track newly protected memory
    // Note: since mprotect does not change protection keys
    // we need to iterate over all pages to also maintain protection keys
    // in our internal tracking system.
    vkey_t vkey = VKEY_INVALID;
    uintptr_t a;
    uintptr_t s;
    for (a = s = (uintptr_t)addr; a < (uintptr_t)addr + len; a += PAGESIZE) {
        // obtain vkey for current page
        // If page is not tracked yet, this returns VKEY_INVALID
        int pg_vkey = _vkey_for_address_nodidcheck(did, (void*)a);
        if (vkey == pg_vkey) {
            // determine the whole range which uses the same vkey
            continue;
        } else {
            // The key changed. Track this memory range
            if (VKEY_INVALID != vkey) {
                // Update this memory range only if it is already tracked (i.e. vkey!=VKEY_INVALID)
                if (!_track_memory((void*)s, a - s, prot, vkey, _vkey_to_pkey(did, vkey), false, 0, 0, 0)) {
                    ERROR("_pk_mprotect cannot track memory");
                    errno = ENOMEM;
                    goto error;
                }
            }
            s = a;          // Track new range start
            vkey = pg_vkey; // Track new range's protection key
        }
    }
    if (VKEY_INVALID != vkey) {
        // Update final memory range only if already tracked
        // In the simplest case, this is the whole address range using the same single pkey
        if (!_track_memory((void*)s, a - s, prot, vkey, _vkey_to_pkey(did, vkey), false, 0, 0, 0)) {
            ERROR("_pk_mprotect cannot track final memory");
            errno = ENOMEM;
            goto error;
        }
    }

    _pk_release_lock();
    return 0;

error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_register_ecall(int ecall_id, void* entry){
    return _pk_domain_register_ecall2(PK_DOMAIN_CURRENT, ecall_id, entry);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_register_ecall2(int did, int ecall_id, void* entry){
    return _pk_domain_register_ecall3(did, ecall_id, entry, NULL);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_register_ecall3(int did, int ecall_id, void* entry, char* name){
    assert(pk_data.initialized);

    _pk_acquire_lock();
    if (PK_DOMAIN_CURRENT == did) {
        did = CURRENT_DID;
    }

    if(!_domain_exists(did)){
        ERROR("Domain does not exist");
        errno = EINVAL;
        goto error;
    }

    // did must be current domain or child
    if(!_domain_is_current_or_child(did)){
        ERROR("only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    int ret = _pk_domain_register_ecall3_unlocked(did, ecall_id, entry, name);
    _pk_release_lock();
    return ret;

error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_register_ecall3_unlocked(int did, int ecall_id, void* entry, char* name){
    DEBUG_MPK("_pk_domain_register_ecall3(%d, %d, %p, %s)", did, ecall_id, entry, name);

    // obtain next free ecall_id
    if (PK_ECALL_ANY == ecall_id) {
        for (ecall_id = 0; ecall_id < NUM_REGISTERED_ECALLS; ecall_id++) {
            if (!pk_registered_ecalls[ecall_id].entry) {
                // We found an empty ecall slot
                break;
            }
        }
    }

    // check for valid id
    if(ecall_id < 0 || ecall_id >= NUM_REGISTERED_ECALLS){
        ERROR("ecall_id is out of range");
        errno = EACCES;
        goto error;
    }

    if(pk_registered_ecalls[ecall_id].entry != 0){
        ERROR("ecall_id already used");
        errno = EACCES;
        goto error;
    }

    // register ecall
    pk_registered_ecalls[ecall_id].did   = did;
    pk_registered_ecalls[ecall_id].entry = entry;
    pk_registered_ecalls[ecall_id].name  = name;
    return ecall_id;

error:
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_allow_caller(int caller_did, unsigned int flags){
    return _pk_domain_allow_caller2(PK_DOMAIN_CURRENT, caller_did, flags);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_allow_caller2(int did, int caller_did, unsigned int flags){
    assert(pk_data.initialized);
    _pk_acquire_lock();

    if (PK_DOMAIN_CURRENT == did) {
      did = CURRENT_DID;
    }

    if(!_domain_exists(did)){
        ERROR("_pk_domain_allow_caller2: domain does not exist");
        errno = EINVAL;
        goto error;
    }

    // only allowed if we're the target or its parent
    if(!_domain_is_current_or_child(did)){
        ERROR("_pk_domain_allow_caller2 only allowed on self or children");
        errno = EACCES;
        goto error;
    }

    int ret = _pk_domain_allow_caller2_unlocked(did, caller_did, flags);
    _pk_release_lock();
    return ret;

error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_allow_caller2_unlocked(int did, int caller_did, unsigned int flags){
    DEBUG_MPK("_pk_domain_allow_caller2(%d, %d, %u)", did, caller_did, flags);

    if (flags) {
        ERROR("_pk_domain_allow_caller2: invalid flags");
        errno = EINVAL;
        goto error;
    }

    if(!_domain_exists(caller_did)){
        ERROR("_pk_domain_allow_caller2: Caller domain does not exist");
        errno = EINVAL;
        goto error;
    }

    if (_is_allowed_source_nodidcheck(caller_did, did)) {
        DEBUG_MPK("_pk_domain_allow_caller2 already allowed, doing nothing.");
    } else {
        size_t * count = &(pk_data.domains[did].allowed_source_domains_count);
        if(*count >= NUM_SOURCE_DOMAINS){
            ERROR("_pk_domain_allow_caller2: no more slots available");
            errno = ENOMEM;
            goto error;
        }
        pk_data.domains[did].allowed_source_domains[*count] = caller_did;
        (*count)++;
    }

    return 0;

error:
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE  _pk_domain_load_key(vkey_t vkey, int slot, unsigned int flags){
    DEBUG_MPK("_pk_domain_load_key(%d, %d, %u)", vkey, slot, flags);
    assert(pk_data.initialized);
    _pk_acquire_lock();
    int ret = _pk_domain_load_key_unlocked(CURRENT_DID, vkey, slot, flags);
    _pk_release_lock();
    return ret;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_load_pkkey_unlocked(int did, pk_key_t * key, int slot){
    DEBUG_MPK("_pk_domain_load_pkkey_unlocked(did=%d, key=[%d %d %d], slot=%d)", did, key->vkey, key->pkey, key->perm, slot);

    if (!_thread_domain_initialized(did)) {
        DEBUG_MPK("Initializing thread domain");
        _pk_get_thread_domain_data_nodidcheck(did);
    }

    if (0 != _pk_domain_load_key_arch(did, key->pkey, slot, key->perm)){
        return -1;
    }
    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE  _pk_domain_load_key_unlocked(int did, vkey_t vkey, int slot, unsigned int flags){
    DEBUG_MPK("_pk_domain_load_key_unlocked(%d, %d, %d, %u)", did, vkey, slot, flags);

    if (0 != flags) {
        ERROR("_pk_domain_load_key invalid flags");
        errno = EINVAL;
        return -1;
    }

    if(PK_DEFAULT_KEY == vkey){
        vkey = _get_default_vkey(did);
        if (VKEY_INVALID == vkey) {
            ERROR("_pk_domain_load_key domain has no default key");
            errno = EACCES;
            return -1;
        }
    }

    pk_key_t * pkkey = _domain_get_pk_key_t(did, vkey);
    if (NULL == pkkey){
        ERROR("_pk_domain_load_key domain does not have pkey");
        errno = EACCES;
        return -1;
    }

    if (0 != _pk_domain_load_pkkey_unlocked(did, pkkey, slot)){
        return -1;
    }

    return 0;
}
//------------------------------------------------------------------------------

PK_DATA int _pthread_child_has_signalled = 0;

void PK_CODE _pthread_init_function_c(void * start_routine, void * current_user_stack) {
  DEBUG_MPK("_pthread_init_function_c(%p, %p)", pk_data.pthread_arg.start_routine, pk_data.pthread_arg.arg);

  // initialize thread
  int ret = _pk_init_thread(pk_data.pthread_arg.current_did, pk_data.pthread_arg.exception_stack);
  if (ret) {
    ERROR("_pthread_init_function_c: unable to initialize thread");
    // errno is set by _pk_init_thread
    goto error;
  }

  // enable thread for startup
  _pk_domain_switch(TYPE_CALL, CURRENT_DID, start_routine, current_user_stack);
  goto done;

error:
  // enable thread for self-destruction
  _pk_domain_switch(TYPE_CALL, CURRENT_DID, PTHREAD_EXIT, current_user_stack);

done:
  assert(0 == pthread_mutex_lock(&pk_data.condmutex));
  _pthread_child_has_signalled = 1;
  assert(0 == pthread_mutex_unlock(&pk_data.condmutex));
  assert(0 == pthread_cond_signal(&pk_data.cond));
  DEBUG_MPK("_pthread_init_function_c done");
}
//------------------------------------------------------------------------------

int PK_CODE _pk_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg)
{
  DEBUG_MPK("_pk_pthread_create(%p, %p, %p, %p)", thread, attr, start_routine, arg);
  int ret;
  assert(pk_data.initialized);
  _pk_acquire_lock();

  if (!thread || !start_routine) {
    ERROR("_pk_pthread_create: thread or start_routine is NULL");
    ret = EINVAL;
    goto error1;
  }

  if(!_domain_owns_memory(CURRENT_DID, thread, sizeof(thread))) {
    ERROR("_pk_pthread_create: *thread is not owned by current domain");
    ret = EINVAL;
    goto error1;
  }

  // If we want to support attr properly, we need to check whether
  // _domain_owns_memory(*attr) and _domain_owns_memory(internal stack of *attr)
//   if (attr) {
//     ERROR("_pk_pthread_create does not support attributes");
//     ret = EINVAL;
//     goto error1;
//   }

  // *start_routine needs no check since it is only interpreted by user code

  // *arg needs no check since it is only interpreted by user code

  // setup exception stack
  void* exception_stack_base = _pk_setup_thread_exception_stack();
  if (!exception_stack_base) {
    ERROR("_pk_pthread_create: failed to setup exception stack");
    ret = EAGAIN;
    goto error1;
  }

  pk_data.pthread_arg.exception_stack = (uintptr_t*)exception_stack_base; 
  pk_data.pthread_arg.exception_stack_top = (uintptr_t*)exception_stack_base + EXCEPTION_STACK_WORDS - 2;
  pk_data.pthread_arg.arg = arg;
  pk_data.pthread_arg.start_routine = start_routine;
  pk_data.pthread_arg.current_did = CURRENT_DID;

  assert(0 == _pthread_child_has_signalled);
  ret = PTHREAD_CREATE(thread, attr, _pthread_init_function_asm, arg);
  if (ret) {
    goto error2;
  }

  // wait for child setup being finished
  assert(0 == pthread_mutex_lock(&pk_data.condmutex));
  while (_pthread_child_has_signalled == 0) {
    assert(0 == pthread_cond_wait(&pk_data.cond, &pk_data.condmutex));
  }
  _pthread_child_has_signalled = 0;
  assert(0 == pthread_mutex_unlock(&pk_data.condmutex));

  _pk_release_lock();
  return 0;

error2:
  pthread_mutex_unlock(&pk_data.condmutex);
error1:
  _pk_release_lock();
  return ret;
}
//------------------------------------------------------------------------------

void PK_CODE _pk_pthread_exit_c(void* retval) {
  DEBUG_MPK("_pk_pthread_exit_c(%p)", retval);
  // Currently, by calling pthread_exit directly, threads can exit
  // However, the exception stack is not free'd.

  // Prepare thread for continuing at pthread_exit
  _pk_acquire_lock();

  // mark tid as exiting thread
  int tid = pk_trusted_tls.tid;
  pk_trusted_tls.exiting = 1;            // Mark TTLS as exiting such that sysfilter can skip this thread
  pk_data.threads[tid] = THREAD_EXITING; // Make TTLS pointer unusable

  // unprotect TTLS
  uintptr_t ttls_start, ttls_end;
  _get_current_ttls_range(&ttls_start, &ttls_end);
  DEBUG_MPK("unprotecting TTLS from %p to %p", (void*)ttls_start, (void*)ttls_end);
  int ret = _pk_pkey_munprotect_unlocked(DID_FOR_EXCEPTION_HANDLER, (void*)ttls_start, ttls_end - ttls_start, PROT_WRITE | PROT_READ);
  assert(ret == 0);

  // the next instruction in the domain is calling pthread_exit
  _pk_domain_switch(TYPE_CALL, CURRENT_DID, PTHREAD_EXIT, pk_trusted_tls.backup_user_stack);
  //assert(false);
  _pk_release_lock();
}
//------------------------------------------------------------------------------

int PK_CODE _pk_register_exception_handler(void (*handler)(void*)) {
  DEBUG_MPK("_pk_register_exception_handler(%p)", handler);
  assert(pk_data.initialized);

  _pk_acquire_lock();

  if (!handler) {
    ERROR("_pk_register_exception_handler: empty handler");
    errno = EINVAL;
    goto error;
  }

  if (!_domain_owns_memory(CURRENT_DID, handler, WORDSIZE)) {
    ERROR("_pk_register_exception_handler: domain does not own handler %p", (void*)handler);
    errno = EACCES;
    goto error;
  }

  if (pk_data.user_exception_handler) {
    ERROR("_pk_register_exception_handler: already configured");
    errno = EPERM;
    goto error;
  }

  pk_data.user_exception_handler = handler;

  _pk_release_lock();
  return 0;

error:
  _pk_release_lock();
  return -1;
}
//------------------------------------------------------------------------------
// Debug-only API functions
//------------------------------------------------------------------------------
char * PK_CODE _pk_get_domain_name(int did){
    if(did == DID_FOR_ROOT_DOMAIN)
        return "ROOT";
    if(did == DID_FOR_EXCEPTION_HANDLER)
        return "EXCEPTION HANDLER";
    return "";
}
char * _pk_domain_str(int did){
    static char buffers[10][256];
    static int buf_idx = 0;

    buf_idx = (buf_idx + 1) % 10;

    char * dom_str = _pk_get_domain_name(did);
    assert(dom_str != NULL);
    int len = sprintf(buffers[buf_idx], "%d %s", did, dom_str);
    assert(len < 256);
    if(strlen(dom_str) == 0){
        buffers[buf_idx][len-1] = '\0'; //remove space
    }
    return buffers[buf_idx];
}
char * PK_CODE _pk_sprint_filter_compact(filter_compact_t * filter_compact, int sysno){
    static char buf[256];
    int len = 0;
    len += sprintf(buf+len, "%3d %-25s flags=%-20s ", 
        sysno,
        sysent_to_syscall_str(&sf_table[sysno]), 
        sysent_flags_str(sf_table[sysno].sys_flags)
    );

    if(filter_compact->filter == SYSCALL_DENIED){
        len += sprintf(buf+len, "DENY");
    }else{
        len += sprintf(buf+len, "filter=%lx filter_did=%d %s", 
            (uint64_t)filter_compact->filter, 
            filter_compact->filter_did, _pk_get_domain_name(filter_compact->filter_did)
        );
    }
    assert(len < (int)sizeof(buf));
    return buf;
}
char * PK_CODE _pk_sprint_sysent(sysent_t * sysent, int sysno){
    static char buf[256];
    int len = 0;
    len += sprintf(buf+len, "%3d %-25s flags=%-20s ", 
        sysno,
        sysent_to_syscall_str(sysent), 
        sysent_flags_str(sysent->sys_flags)
    );

    if(sysent->filter == SYSCALL_DENIED){
        len += sprintf(buf+len, "DENY");
    }else{
        len += sprintf(buf+len, "filter=%lx",
            (uint64_t)sysent->filter
        );
    }
    assert(len < (int)sizeof(buf));
    return buf;
}
void PK_CODE _pk_print_monitor_sysfilters(sysent_t * _sf_table, size_t num){
    for (size_t i = 0; i < num; i++)
    {
        sysent_t * sysent = &(_sf_table[i]);
        filter_t filter = sysent->filter;
        if(filter != SYSCALL_ALLOWED && filter != NULL){
            FPRINTF(stderr, COLOR_GREEN);
            FPRINTF(stderr, "        * %s\n", _pk_sprint_sysent(sysent, i));
            FPRINTF(stderr, COLOR_RESET);
        }
    }
}
void PK_CODE _pk_print_domain_sysfilters(filter_compact_t * _sf_table, size_t num){
    for (size_t i = 0; i < num; i++)
    {
        filter_compact_t * filter_compact = &(_sf_table[i]);
        if(filter_compact->filter != SYSCALL_ALLOWED){
            FPRINTF(stderr, COLOR_GREEN);
            FPRINTF(stderr, "        * %s\n", _pk_sprint_filter_compact(filter_compact, i));
            FPRINTF(stderr, COLOR_RESET);
        }
    }
}
char * PK_CODE _pk_print_keys(int did){
    static char buf[512];
    int len = 0;

    assert(pk_data.domains[did].used);
    _pk_domain* dom = &pk_data.domains[did];

    for (size_t key_id = 0; key_id < NUM_KEYS_PER_DOMAIN; key_id++) {
        if (dom->keys[key_id].used) {
            len += snprintf(buf + len, sizeof(buf) - (size_t)len, "%d-%d(%s%s), ",
                dom->keys[key_id].pkey, dom->keys[key_id].vkey,
                dom->keys[key_id].perm & PKEY_DISABLE_WRITE ? "RO, " : "",
                dom->keys[key_id].owner ? "owner" : "copy"
            );
            assert_ifdebug(len < (int)sizeof(buf));
        }
    }
    //if (pk_trusted_tls.syscall_args_key.used) {
    //    len += snprintf(buf + len, sizeof(buf) - (size_t)len, "[s:%d-%d]", pk_trusted_tls.syscall_args_key.pkey, pk_trusted_tls.syscall_args_key.vkey);
    //}
    assert(len < (int)sizeof(buf));
    return buf;
}
void PK_CODE _pk_print_debug_info2(void* addr, size_t len){
    FPRINTF(stderr, "\n");
    //printf(COLOR_INFO);
    if (pk_trusted_tls.init) {
        // This requires access to CURRENT_DID
        FPRINTF(stderr, "[INFO] current config reg: %s\n", pk_sprint_reg_arch(read_pkru_current_thread(CURRENT_DID)));
    }

    for (size_t tid = 0; tid < NUM_THREADS; tid++) {
        if (THREAD_UNUSED == pk_data.threads[tid] || THREAD_EXITING == pk_data.threads[tid]) {
          continue;
        }
        _pk_tls* thread_data = pk_data.threads[tid];
        int is_current_thread = 1;
        char thread_name[128] = {0,};
        #ifndef PROXYKERNEL
            is_current_thread = thread_data->pthread_tid == pthread_self();
            pthread_getname_np(thread_data->pthread_tid, thread_name, sizeof(thread_name));
        #endif

        FPRINTF(stderr, "[INFO] %sThread %zu (%s):%s exception_stack_base: %p, exception_stack: %p, backup_user_stack: %p, pthread_tid=0x%lx\n",
            is_current_thread ? COLOR_GREEN : "",
            tid,
            thread_name,
            is_current_thread ? COLOR_RESET : "",
            (void*)thread_data->exception_stack_base,
            (void*)thread_data->exception_stack,
            (void*)thread_data->backup_user_stack,
            thread_data->pthread_tid
        );
        if (thread_data->syscall_args_key.used) {
            FPRINTF(stderr, "\t└ syscall_args_key: %d-%d\n", thread_data->syscall_args_key.pkey, thread_data->syscall_args_key.vkey);
        }


        for (size_t did = 0; did < NUM_DOMAINS; did++) {
            if (!pk_data.domains[did].used) {
                continue;
            }
            _pk_thread_domain threaddomaindata = thread_data->thread_dom_data[did];
            if(!threaddomaindata.user_stack_base){
                continue;
            }
            FPRINTF(stderr, "\t└ Domain %zu: user_stack_base/size: %p -- %p\n", 
                did, 
                (void*)threaddomaindata.user_stack_base, 
                (void*)((uintptr_t)threaddomaindata.user_stack_base + threaddomaindata.user_stack_size)
            );

            FPRINTF(stderr, "\t└ current config: %s\n", pk_sprint_reg_arch(read_pkru(did, tid)));

            _expected_return * expected_return = threaddomaindata.expected_return;
            //FPRINTF(stderr, "\t\t└ expected_return:\n");
            while(expected_return){
                FPRINTF(stderr, "\t\t└ expected_return (current thread): did=%d, reentry=%p, previous=%14p",
                    expected_return->did,
                    expected_return->reentry,
                    expected_return->previous
                );
                #ifdef ADDITIONAL_DEBUG_CHECKS
                    FPRINTF(stderr, ", sp=%14p", expected_return->sp);
                #endif
                FPRINTF(stderr, "\n");
                expected_return = expected_return->previous;
            }
        }
    }

    for (size_t did = 0; did < NUM_DOMAINS; did++) {
        if (!pk_data.domains[did].used) {
            continue;
        }
        int is_current_domain = pk_trusted_tls.init && did == (size_t)CURRENT_DID;
        FPRINTF(stderr, "[INFO] %sDomain %zu: %s %s%s\n",
            is_current_domain ? COLOR_GREEN : "",
            did,
            _pk_get_domain_name(did),
            is_current_domain ? "(current domain)" : "",
            is_current_domain ? COLOR_RESET : ""
        );
        _pk_domain* dom = &pk_data.domains[did];

        FPRINTF(stderr, "\t└ parent_did = %d\n", dom->parent_did);

        //FPRINTF(stderr, "\t└ default_config:  %s\n", pk_sprint_reg_arch(dom->default_config));

        FPRINTF(stderr, "\t└ keys: [%s]\n", _pk_print_keys(did));

        FPRINTF(stderr, "\t└ allowed_source_domains: [");
        for (size_t i = 0; i < dom->allowed_source_domains_count; i++) {
            FPRINTF(stderr, "%d, ", dom->allowed_source_domains[i]);
        }
        FPRINTF(stderr, "]\n");
        FPRINTF(stderr, "\t└ syscall filters:\n");
        _pk_print_domain_sysfilters(dom->sf_table, (sizeof(dom->sf_table) / sizeof(filter_compact_t)));
    }

    FPRINTF(stderr, "[INFO] monitor syscall filters:\n");
    _pk_print_monitor_sysfilters(sf_table, NUM_MONITOR_FILTERS);

    FPRINTF(stderr, "[INFO] Memory ranges:\n");
    for (size_t range_id = 0; range_id < NUM_MPROTECT_RANGES; range_id++) {
        mprotect_t range = pk_data.ranges[range_id];
        if (range.used) {
            if(addr && _memory_overlaps(addr, len, range.addr, range.len)){ fprintf(stderr, COLOR_RED);}
            FPRINTF(stderr, "\t└ %4zu: addr=%16p -- %16p, len=0x%8zx, prot=%2d %-5s, key=%2d-%2d, flags=%d, fd=%d, offset=%zu. %s\n", 
                range_id, range.addr, 
                (void*)((uintptr_t)range.addr + range.len), 
                range.len, range.prot, _mprotect_prot_to_str(range.prot), 
                range.pkey, range.vkey,
                range.mmap_flags, range.mmap_fd, range.mmap_offset,
                range.name ? range.name : ""
            );
            if(addr && _memory_overlaps(addr, len, range.addr, range.len)){ fprintf(stderr, COLOR_RESET);}

        }
    }

    //FPRINTF(stderr, COLOR_RESET);
    FPRINTF(stderr, "\n");
}

void PK_CODE _pk_print_debug_info(){
    _pk_print_debug_info2(0,0);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_current_did(){
    return CURRENT_DID;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_set_binary_scanning_unlocked(uint64_t arg1){
    assert(arg1 == 0 || arg1 == 1);
    pk_data.binary_scanning = arg1;
    return 0;
}

int PK_CODE _pk_set_binary_scanning(uint64_t arg1){
    DEBUG_MPK("_pk_set_binary_scanning(arg1=%lu", arg1);
    return _pk_set_binary_scanning_unlocked(arg1);
}

int PK_CODE _pk_simple_api_call(int a, int b, int c, int d, int e, int f){
    int ret = a+b+c+d+e+f;
    DEBUG_MPK("_pk_simple_api_call(a=%d, b=%d, c=%d, d=%d, e=%d, f=%d). returning %d", a,b,c,d,e,f, ret);
    return ret;
}

int PK_CODE _pk_api_generic(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6){
    DEBUG_MPK("_pk_api_generic(arg1=%lu, arg2=%lu, arg3=%lu, arg4=%lu, arg5=%lu, arg6=%lu)\n", arg1, arg2, arg3, arg4, arg5, arg6);
    switch (arg1)
    {
    case 1:
        {
            //register file path to domain
            int domain = (int) arg2;
            char * path = (char *) arg3;
            if (PK_DOMAIN_CURRENT == domain) {
                domain = CURRENT_DID;
            }
            _pk_acquire_lock();
            if(!_domain_is_current_or_child(domain)){
                WARNING("bad domain %d.\n", domain);
                _pk_release_lock();
                return -1;
            }
            for (size_t i = 0; i < NUM_PRIVATE_FILES; i++) {
                if(pk_data.private_files[i].path == NULL){
                    pk_data.private_files[i].path   = strdup(path);
                    pk_data.private_files[i].domain = domain;
                    DEBUG_MPK("registered private file %s for domain %d.\n", path, domain);
                    _pk_release_lock();
                    return 0;
                }
            }
            WARNING("failed to register private file %s for domain %d.\n", path, domain);
            _pk_release_lock();
            return -1;
        }
        break;
    default:
        break;
    }
    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_unused(){
    ERROR("This API call is not implemented");
    errno = ENOSYS;
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_domain_register_sysfilter_unlocked(int did, int sys_nr, filter_t filter, arg_copy_t arg_copy[]){
    if (!_domain_exists(did)) {
        errno = EINVAL;
        return -1;
    }

    if (PK_DOMAIN_CURRENT == did) {
        did = CURRENT_DID;
    }

    if (!_domain_is_child(did)) {
      ERROR("_pk_domain_register_sysfilter_unlocked only allowed on children");
      errno = EACCES;
      return -1;
    }

    if (sys_nr < 0 || sys_nr >= (int)NUM_MONITOR_FILTERS) {
      ERROR("_pk_domain_register_sysfilter_unlocked: invalid sys_nr");
      errno = EINVAL;
      return -1;
    }

    int filter_did = CURRENT_DID;

#ifndef RELEASE
    vkey_t vkey_for_filtercode = _vkey_for_address_no_permission_check(filter);
    if( (long)filter >= 0 //filter function supplied
        && vkey_for_filtercode != 0 //filter code is protected with a pkey
        && ! _domain_has_vkey_nodidcheck(filter_did, vkey_for_filtercode) //domain doesnt have the pkey
    ){
        ERROR("vkey_for_filtercode = %d", vkey_for_filtercode);
        ERROR("filter_did = %d", filter_did);
        ERROR("_domain_has_vkey_nodidcheck(filter_did, vkey_for_filtercode) = %d", _domain_has_vkey_nodidcheck(filter_did, vkey_for_filtercode));
        ERROR("Cannot install filter (which may lie in pk_code)! Domain %s may not have the necessary key for %p!", _pk_domain_str(filter_did), filter);
    }
#endif /* RELEASE */

    _pk_domain *domain = &pk_data.domains[did];
    domain->sf_table[sys_nr].filter = filter;
    domain->sf_table[sys_nr].filter_did = filter_did;
    if (arg_copy != NULL) {
        pk_memcpy(domain->sf_table[sys_nr].arg_copy, arg_copy, SYSCALL_ARG_COUNT * sizeof(arg_copy_t));
    } else {
        memset(domain->sf_table[sys_nr].arg_copy, 0, SYSCALL_ARG_COUNT * sizeof(arg_copy_t));
    }
    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_sysfilter_module_intercept(int sysno) {
    if (!pk_sysfilter_module) {
		return 0;
	}

    if (sysfilter_fd < 0) {
        WARNING("Sysfilter module not opened. Cannot intercept syscall %d", sysno);
        errno = EACCES;
        return -1;
    }

    DEBUG_MPK("Block syscall number %d", sysno);
    if (-1 == ioctl(sysfilter_fd, SYSFILTER_IOCTL_CMD_BLOCK, sysno)) {
        WARNING("Apply sysfilter to PID  %d failed", sysfilter_pid);
        // errno set by ioctl
        return -1;
    }
    return 0;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_sysfilter_domain(int did, int sys_nr, filter_t filter, arg_copy_t arg_copy[]){
    DEBUG_MPK("_pk_sysfilter_domain(%d, %d, %p, %s)", did, sys_nr, filter, arg_copy_str(arg_copy));
    assert(pk_data.initialized);

    _pk_acquire_lock();

    if (!sf_data.sf_filters_initialized) {
        ERROR("SF filters are not initialized yet");
        errno = EACCES;
        goto error;
    }

    if (-1 == _pk_domain_register_sysfilter_unlocked(did, sys_nr, filter, arg_copy)) {
        ERROR("Registering domain sysfilter failed");
        //errno set by _pk_domain_register_sysfilter_unlocked
        goto error;
    }

    if (-1 == _pk_sysfilter_module_intercept(sys_nr)) {
        ERROR("Sysfilter cannot intercept syscall %d", sys_nr);
        //errno set by _pk_sysfilter_module_intercept
        goto error;
    }

    _pk_release_lock();
    return 0;

error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_sysfilter_monitor(int sys_nr, filter_t filter, arg_copy_t arg_copy[]){
    DEBUG_MPK("_pk_sysfilter_monitor(%d, %p, %s)", sys_nr, filter, arg_copy_str(arg_copy));
    assert(pk_data.initialized);

    _pk_acquire_lock();

    if (!sf_data.sf_filters_initialized) {
        ERROR("SF filters are not initialized yet");
        errno = EACCES;
        goto error;
    }

    if (sf_table[sys_nr].filter != SYSCALL_UNSPECIFIED) {
        DEBUG_SF("Overwriting monitor filter");
    }
    sf_table[sys_nr].filter = filter;
    if (arg_copy != NULL) {
        pk_memcpy(sf_table[sys_nr].arg_copy, arg_copy, SYSCALL_ARG_COUNT * sizeof(arg_copy_t));
    } else {
        memset(sf_table[sys_nr].arg_copy, 0, SYSCALL_ARG_COUNT * sizeof(arg_copy_t));
    }

    if (-1 == _pk_sysfilter_module_intercept(sys_nr)) {
        ERROR("Sysfilter cannot intercept syscall %d", sys_nr);
        //errno set by _pk_sysfilter_module_intercept
        goto error;
    }

    _pk_release_lock();
    return 0;
error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_sysfilter_tracer(tracer_t tracer, pid_t tracee)
{
    DEBUG_MPK("_pk_sysfilter_tracer(%p)", tracer);
    assert(pk_data.initialized);

    _pk_acquire_lock();

    if (pk_data.tracer_started) {
        _pk_release_lock();
        ERROR("only a single tracer can be started");
        errno = EPERM;
        return -1;
    }

    pk_data.tracer_started = 1;
    _pk_release_lock();

    int return_value = tracer(tracee);
    return return_value;
}
//------------------------------------------------------------------------------

#define UCONTEXT_PRINT_GREG(reg) \
    printf(#reg "[%3d]: %16llx\n", reg, ucontext->uc_mcontext.gregs[reg]);

//------------------------------------------------------------------------------

void PK_CODE _pk_signal_framecpy(ucontext_t* dst, ucontext_t* src) {
    pk_memcpy(dst, src, sizeof(ucontext_t));

    // We currenly do not copy these substructures
    assert_ifdebug(NULL == (void*)(src->uc_link));
    //assert_ifdebug(NULL == ((ucontext_t*)sigframe)->uc_stack.ss_sp);

    if (src->uc_mcontext.fpregs) {
        uintptr_t fpregs_offset = (uintptr_t)src->uc_mcontext.fpregs - (uintptr_t)src;
        dst->uc_mcontext.fpregs = (void*)((uintptr_t)dst + fpregs_offset);
        // Check that fpregs points into ucontext_t
        assert_ifdebug((uintptr_t)dst->uc_mcontext.fpregs >= (uintptr_t)dst);
        assert_ifdebug((uintptr_t)dst->uc_mcontext.fpregs < (uintptr_t)dst + sizeof(ucontext_t));
    }
}
//------------------------------------------------------------------------------

// Delegate signal to monitor
void PK_CODE _pk_sigaction_trampoline(int signum, siginfo_t* siginfo, void* sigframe) {
    // All signals are already blocked for this thread
    // We ensure this during sigaction registration

    // Ensure that we have full PKRU access such that we can write to monitor's trusted tls
    ENSURE_FULL_PKRU_ACCESS();

#ifndef RELEASE
    DEBUG_MPK("_pk_sigaction_handler(%d=%s)", signum, strsignal(signum));
    ENSURE_FULL_PKRU_ACCESS(); // Any debug statement might ruin PKRU access, so redo it
#endif
    if (pk_trusted_tls.signal_state != SIGNAL_NONE) {
        ERROR_FAIL("Too many signals received. We do not support signal nesting");
    }
    if (pk_trusted_tls.filter_syscalls || pk_trusted_tls.signal_pending == SIGNAL_DEFERRED) {
        // We are in domain mode or just deferred a signal to the end of the monitor
        // Deliver signal to monitor
        pk_trusted_tls.signal_siginfo = siginfo;
        pk_trusted_tls.signal_sigframe = sigframe;
        pk_trusted_tls.signal_state = SIGNAL_ACTIVE;
        _pk_signal_handler();
    } else {
        // We are in monitor mode
        // Signal arrived due to one of the following reasons:
        // a) We made a mistake in monitor code (e.g., SIGSEGV)
        // b) We impersonated a signalling syscall (e.g., (tg)kill)
        // c) We got an asynchronous signal (e.g., SIGALRM)
        if (signum == SIGSEGV) {
            // a) Kill the program
            ENSURE_FULL_PKRU_ACCESS(); // Any debug statement might ruin PKRU access, so redo it
            assert(false);
        }
        // b+c) Defer signal until monitor finishes

        // Discard siginfo/sigframe as they might present information leakage

        // Set signal on monitor's signal_pending
        assert_ifdebug(pk_trusted_tls.signal_pending == 0);
        pk_trusted_tls.signal_pending = signum;

        // Save the signal mask
        pk_trusted_tls.signal_mask = ((ucontext_t*)sigframe)->uc_sigmask;

#ifdef RELEASE
        // Block all signals when leaving this handler
        sigfillset(&((ucontext_t*)sigframe)->uc_sigmask);
#else
        // For GDB debugging only block the present signal
        sigaddset(&((ucontext_t*)sigframe)->uc_sigmask, signum);
#endif

        // Redeploy signal:
        // We cannot invoke _pk_signal_handler directly but let the monitor finish its work.
        // The monitor will:
        // * fetch signal from signal_pending
        // * redeploy signal using tgkill (it is still blocked)
        // * restore signal mask. At this point, the signal will be delivered
    }
}
//------------------------------------------------------------------------------

int PK_CODE _pk_sigaction_internal_unlocked(int did, int signum, const struct sigaction *act,
                                            struct sigaction *oldact) {
    DEBUG_MPK("_pk_sigaction(%d=%s)", signum, strsignal(signum));

    if (signum < 0 || signum >= MAX_SIGNO) {
        ERROR("signum out of range");
        errno = EINVAL;
        return -1;
    }

    // did must be current domain or child
    if(!_domain_is_current_or_child(did)){
        ERROR("only allowed on current domain or child");
        errno = EACCES;
        return -1;
    }

    if (pk_signal_did[signum] != DID_INVALID) {
        // can only override child-registered handlers
        if(!_domain_is_current_or_child(pk_signal_did[signum])){
            ERROR("only allowed to override current domain or child");
            errno = EACCES;
            return -1;
        }
    }

    int newdid = DID_INVALID;
    if (oldact) {
        *oldact = pk_signal_action[signum];
    }
    if (!act) {
        // Nothing to register, just return
        return 0;
    }

    struct sigaction newact = *act;
    if (newact.sa_flags & SA_SIGINFO) {
        // Hook action with our own handler
        newact.sa_sigaction = _pk_sigaction_trampoline;
        newdid = did;
        DEBUG_MPK("registering sigaction");
    } else {
        // We leave SIG_DFL and SIG_IGN unchanged
        if (newact.sa_handler != SIG_DFL && newact.sa_handler != SIG_IGN) {
            // Hook action with our own handler
            newact.sa_flags |= SA_SIGINFO;
            newact.sa_sigaction = _pk_sigaction_trampoline;
            newdid = did;
            DEBUG_MPK("registering signal");
        } else {
            DEBUG_MPK("deregistering/ignoring signal");
        }
    }

    // Block all signals for the duration of being on the sigaltstack
    sigfillset(&newact.sa_mask);
    newact.sa_flags |= SA_ONSTACK;

    int ret = SIGACTION(signum, &newact, NULL);
    if (0 == ret) {
        pk_signal_action[signum] = *act;
        pk_signal_did[signum] = newdid;
    }
    DEBUG_MPK("SIGACTION(%d, '%s') returned: %d", signum, strsignal(signum), ret);
    return ret;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_sigaction2(int did, int signum, const struct sigaction *act,
                          struct sigaction *oldact) {
    DEBUG_MPK("_pk_sigaction2(%d=%s)", signum, strsignal(signum));
    assert(pk_data.initialized);
    _pk_acquire_lock();

    if (PK_DOMAIN_CURRENT == did) {
      did = CURRENT_DID;
    }

    if(act && !_pk_domain_can_access_memory_syscall(did, act, sizeof(struct sigaction), false)) {
        ERROR("*act is not accessible by domain");
        errno = EINVAL;
        goto error;
    }

    if(oldact && !_pk_domain_can_access_memory_syscall(did, oldact, sizeof(struct sigaction), true)) {
        ERROR("*oldact is not accessible by domain");
        errno = EINVAL;
        goto error;
    }

    int ret = _pk_sigaction_internal_unlocked(did, signum, act, oldact);

    _pk_release_lock();
    return ret;

error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

int PK_CODE _pk_sigaction(int signum, const struct sigaction *act,
                          struct sigaction *oldact) {
    return _pk_sigaction2(PK_DOMAIN_CURRENT, signum, act, oldact);
}
//------------------------------------------------------------------------------

int PK_CODE _pk_sigaction_krnl2(int did, int signum, const struct kernel_sigaction *kact,
                                struct kernel_sigaction *koldact) {
    DEBUG_MPK("_pk_sigaction_krnl(%d=%s)", signum, strsignal(signum));
    assert(pk_data.initialized);
    _pk_acquire_lock();

    if (PK_DOMAIN_CURRENT == did) {
      did = CURRENT_DID;
    }

    if(kact && !_pk_domain_can_access_memory_syscall(did, kact, sizeof(struct kernel_sigaction), false)) {
        ERROR("*act is not accessible by domain");
        errno = EINVAL;
        goto error;
    }

    if(koldact && !_pk_domain_can_access_memory_syscall(did, koldact, sizeof(struct kernel_sigaction), true)) {
        ERROR("*oldact is not accessible by domain");
        errno = EINVAL;
        goto error;
    }

    struct sigaction act;
    struct sigaction oldact;
    struct sigaction* pact = NULL;
    struct sigaction* poldact = NULL;

    if (kact) {
        act.sa_handler  = (void*)kact->k_sa_handler;
        act.sa_flags    = kact->sa_flags;
        act.sa_mask     = kact->sa_mask;
        act.sa_restorer = kact->sa_restorer;
        pact = &act;
    }
    if (koldact) {
        poldact = &oldact;
    }

    int ret = _pk_sigaction_internal_unlocked(did, signum, pact, poldact);
    if (0 == ret && koldact) {
        koldact->k_sa_handler = oldact.sa_handler;
        koldact->sa_flags     = oldact.sa_flags;
        koldact->sa_mask      = oldact.sa_mask;
        koldact->sa_restorer  = oldact.sa_restorer;
    }
    _pk_release_lock();
    return ret;

error:
    _pk_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

__sighandler_t PK_CODE _pk_signal2(int did, int signum, sighandler_t handler)
{
    DEBUG_MPK("_pk_signal2(%d=%s)", signum, strsignal(signum));
    assert(pk_data.initialized);

    _pk_acquire_lock();

     if (PK_DOMAIN_CURRENT == did) {
      did = CURRENT_DID;
    }

    struct sigaction oldact;
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = handler;

    if (0 != _pk_sigaction_internal_unlocked(did, signum, &act, &oldact)) {
        // errno set by _pk_sigaction
        goto error;
    }
    _pk_release_lock();
    return oldact.sa_handler;

error:
    _pk_release_lock();
    return SIG_ERR;
}
//------------------------------------------------------------------------------

__sighandler_t PK_CODE _pk_signal(int signum, sighandler_t handler) {
    return _pk_signal2(PK_DOMAIN_CURRENT, signum, handler);
}
//------------------------------------------------------------------------------

void PK_CODE _pk_signal_handler_c() {
    DEBUG_MPK("pk_signal_handler_c called");
    _pk_acquire_lock();

    
    if (pk_trusted_tls.signal_state != SIGNAL_ACTIVE) {
        ERROR_FAIL("No signal active");
    }
    int signo = pk_trusted_tls.signal_siginfo->si_signo;
    if (signo < 0 || signo > MAX_SIGNO) {
        ERROR_FAIL("Invalid signo %d", signo);
    }
    // store interrupted did for later resumption
    pk_trusted_tls.signal_sigdid = CURRENT_DID;
    int did = pk_signal_did[signo];
    if (did < 0 || did >= NUM_DOMAINS) {
        ERROR_FAIL("Invalid did %d", did);
    }
    struct sigaction act = pk_signal_action[signo];
    void* handler = NULL;
    if (act.sa_flags & SA_SIGINFO) {
        handler = act.sa_sigaction;
    } else {
        handler = act.sa_handler;
    }

    _pk_thread_domain* source_thread_domain = &(pk_trusted_tls.thread_dom_data[CURRENT_DID]); // CURRENT_DID exists for sure, so we do a faster lookup than _pk_get_thread_domain_data_nodidcheck(CURRENT_DID);
    source_thread_domain->user_stack = SYSCALL_STACK; // store the sigaltstack rsp s.t. we can resume in _pk_signal_handler_exit_c

    _pk_thread_domain* target_thread_domain = _pk_get_thread_domain_data_nodidcheck(did); // can be same as source_user_stack
    void* target_user_stack = NULL;
    if (did == CURRENT_DID) {
        // we handle the signal in the same domain
        // Thus, we need to recover the interrupted RSP from the sigframe such that we do not operate on the sigaltstack
        target_user_stack = (void*)pk_trusted_tls.signal_sigframe->uc_mcontext.gregs[REG_RSP];
    } else {
        // we switch to a different domain that handles the signal
        target_user_stack = (uint64_t *) GET_USER_STACK(target_thread_domain);
    }

    // align our stack to 16 bytes
    target_user_stack = (void*)ROUNDDOWN(target_user_stack, 16);
    assert_ifdebug(((uintptr_t)target_user_stack % 16) == 0);

    siginfo_t* siginfo = NULL;
    ucontext_t* sigframe = NULL;
    if (act.sa_flags & SA_SIGINFO) {
        if (unlikely(!_user_stack_push_allowed(target_thread_domain, (uintptr_t)target_user_stack, sizeof(siginfo_t) /* + sizeof(ucontext_t) */))) {
            errno = EINVAL;
            ERROR_FAIL("Stack too small to push sigstructs");
        }

        // push siginfo_t onto user stack
        target_user_stack -= ROUNDUP(sizeof(siginfo_t), 16);
        siginfo = target_user_stack;
        pk_memcpy(siginfo, pk_trusted_tls.signal_siginfo, sizeof(siginfo_t));
    }

    // misalign our stack to 8 bytes
    target_user_stack -= sizeof(uint64_t);
    assert_ifdebug(((uintptr_t)target_user_stack % 16) == 8);

    _pk_domain_switch(TYPE_SIGNAL_ENTER, did, _pk_signal_handler_domain, target_user_stack);
    _pk_domain_switch_prepare_call((uint64_t)signo, (uint64_t)siginfo, (uint64_t)sigframe, (uint64_t)handler, 0, 0);

    _pk_release_lock();
}
//------------------------------------------------------------------------------

void PK_CODE _pk_signal_handler_exit_c()
{
    DEBUG_MPK("pk_signal_handler_exit_c called");
    _pk_acquire_lock();

    if (pk_trusted_tls.signal_state != SIGNAL_ACTIVE) {
        ERROR_FAIL("no signal active");
    }
    int did = pk_trusted_tls.signal_sigdid;
    _pk_thread_domain* source_thread_domain = &(pk_trusted_tls.thread_dom_data[did]); // _pk_get_thread_domain_data_nodidcheck(did);
    void* source_user_stack = (uint64_t *) GET_USER_STACK(source_thread_domain);

    if (pk_trusted_tls.signal_pending == SIGNAL_DEFERRED) {
        pk_trusted_tls.signal_pending = 0;
    }

    /* We resume at the original signal handler, which we assume to be secure
     * (i.e., having a monitor-protected stack)
     * 
     * We restore the original domain but keep the monitor pkru in order to access the signal stack
     * The signal handler will execute rt_sigreturn
     * Having monitor pkru settings prevents rt_sigreturn from being sysfiltered and
     * allows it to access the signal frame.
     * 
     * Incompatibility: seccomp_user: cannot access pkru settings of filtered thread, and cannot use tls->filter_syscalls,
     * as this variable is not atomically reset when performing rt_sigreturn
    */
    pk_trusted_tls.signal_state = SIGNAL_RESUME;
    pk_trusted_tls.signal_siginfo = NULL;
    pk_trusted_tls.signal_sigframe = NULL;
    _pk_domain_switch(TYPE_SIGNAL_RETMONITOR, did, NULL, source_user_stack);
    _pk_release_lock();
}
//------------------------------------------------------------------------------

void PK_CODE _pk_signal_prepare_sigprocmask() {
    assert_ifdebug(pk_trusted_tls.signal_pending > 0);
    int signo = pk_trusted_tls.signal_pending;
    // We assume that the thread's kernel sigprocmask is already
    // configured to block all signals, so we can re-deploy the pending
    // signal now to the current thread
    syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), signo);
    pk_trusted_tls.signal_pending = SIGNAL_DEFERRED;

    // prepare arguments for sigprocmask syscall
    // sigprocmask(SIG_SETMASK, &pk_trusted_tls.signal_mask, NULL, NSIG/8)
    pk_trusted_tls.argframe.arg0 = SYS_rt_sigprocmask;
    pk_trusted_tls.argframe.arg1 = SIG_SETMASK;
    pk_trusted_tls.argframe.arg2 = (uint64_t)&pk_trusted_tls.signal_mask;
    pk_trusted_tls.argframe.arg3 = (uint64_t)NULL;
    pk_trusted_tls.argframe.arg4 = NSIG/8;
}
//------------------------------------------------------------------------------

PK_DATA void (*_pk_api_table[API_TABLE_SIZE]) = {
    [_API_pk_my_debug_check]             = _pk_my_debug_check,
    [_API_pk_deinit]                     = _pk_deinit,
    [_API_pk_current_did]                = _pk_current_did,
    [_API_pk_register_exception_handler] = _pk_register_exception_handler,
    [_API_pk_api_generic]                = _pk_api_generic,
    [_API_pk_domain_create]              = _pk_domain_create,
    [_API_pk_domain_free]                = _pk_domain_free,
    [_API_pk_domain_release_child]       = _pk_domain_release_child,
    [_API_pk_set_binary_scanning]        = _pk_set_binary_scanning,
    [_API_unused9]                       = _pk_unused,
    [_API_pk_pkey_alloc]                 = _pk_pkey_alloc,
    [_API_pk_pkey_free]                  = _pk_pkey_free,
    [_API_pk_pkey_mprotect]              = _pk_pkey_mprotect,
    [_API_pk_pkey_mprotect2]             = _pk_pkey_mprotect2,
    [_API_unused14]                      = _pk_unused,
    [_API_unused15]                      = _pk_unused,
    [_API_unused16]                      = _pk_unused,
    [_API_unused17]                      = _pk_unused,
    [_API_unused18]                      = _pk_unused,
    [_API_unused19]                      = _pk_unused,
    [_API_pk_mmap]                       = _pk_mmap,
    [_API_pk_mmap2]                      = _pk_mmap2,
    [_API_pk_mmap3]                      = _pk_mmap3,
    [_API_pk_munmap]                     = _pk_munmap,
    [_API_pk_munmap2]                    = _pk_munmap2,
    [_API_pk_mprotect]                   = _pk_mprotect,
    [_API_pk_mprotect2]                  = _pk_mprotect2,
    [_API_pk_name_range]                 = _pk_name_range,
    [_API_pk_madvise]                    = _pk_madvise,
    [_API_pk_madvise2]                   = _pk_madvise2,
    [_API_pk_domain_register_ecall3]     = _pk_domain_register_ecall3,
    [_API_pk_domain_register_ecall]      = _pk_domain_register_ecall,
    [_API_pk_domain_register_ecall2]     = _pk_domain_register_ecall2,
    [_API_pk_domain_allow_caller]        = _pk_domain_allow_caller,
    [_API_pk_domain_allow_caller2]       = _pk_domain_allow_caller2,
    [_API_pk_domain_assign_pkey]         = _pk_domain_assign_pkey,
    [_API_pk_domain_default_key]         = _pk_domain_default_key,
    [_API_pk_domain_load_key]            = _pk_domain_load_key,
    [_API_unused37]                      = _pk_unused,
    [_API_unused38]                      = _pk_unused,
    [_API_unused39]                      = _pk_unused,
    [_API_pk_pthread_create]             = _pk_pthread_create,
    [_API_pk_pthread_exit]               = _pk_pthread_exit,
    [_API_pk_print_debug_info]           = _pk_print_debug_info,
    [_API_pk_simple_api_call]            = _pk_simple_api_call,
    [_API_unused44]                      = _pk_unused,
    [_API_pk_sysfilter_domain]           = _pk_sysfilter_domain,
    [_API_pk_sysfilter_monitor]          = _pk_sysfilter_monitor,
    [_API_pk_sysfilter_tracer]           = _pk_sysfilter_tracer,
    [_API_sf_filters_init]               = _sf_filters_init,
    [_API_sf_write_results]              = _sf_write_results,
    [_API_pk_sigaction]                  = _pk_sigaction,
    [_API_pk_sigaction2]                 = _pk_sigaction2,
    [_API_pk_signal]                     = _pk_signal,
    [_API_pk_signal2]                    = _pk_signal2,
    [_API_pk_sigaction_krnl2]            = _pk_sigaction_krnl2,
};
//------------------------------------------------------------------------------

void PK_CODE _pk_my_debug_check() {
    DEBUG_MPK("debug check");
}

void PK_CODE __attribute__((noinline)) diehere() {
  volatile int i = 0;
  while(pthread_mutex_trylock(&pk_data.mutex) != 0) i++;
}
