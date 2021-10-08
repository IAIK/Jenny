#pragma once

/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1 //Needed for pthread_getname_np and pthread_getattr_np and for link.h
#endif
//#define GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_RESET   "\x1b[0m"
#define COLOR_INFO    COLOR_CYAN

//Note: Using stderr because unbuffered.
//Otherwise this is needed: setbuf(stdout, NULL);

//#define DONTPRINTANYTHING

#define STDOUT 1
//#define STDERR 1000
#define STDERR 2
extern __thread char debug_buffer[10*4096];
extern __thread char * debug_buffer_ptr;
extern __thread char debug_buffer_thread_name[4096];
extern unsigned long* debug_buffer_process_private;

//------------------------------------------------------------------------------
/*
#if !defined(PROXYKERNEL) //&& defined(pthread_getname_np)
    #define __pthread_getname_np pthread_getname_np
#else
    #define __pthread_getname_np(...)
#endif
#define THREADNAME() ({ __pthread_getname_np(pthread_self(), debug_buffer_thread_name, sizeof(debug_buffer_thread_name)); debug_buffer_thread_name; })
//*/
#define THREADNAME() debug_buffer_thread_name
#define debug_pid (*(unsigned long*)debug_buffer_process_private)


#ifdef RELEASE
static inline void SET_THREAD_NAME(pthread_t thread, const char * name){
}
#else /* RELEASE */
static inline void SET_THREAD_NAME(pthread_t thread, const char * name){
    pthread_t thread_self = pthread_self();
    //assert(strlen(name) < 16);
    if(thread == thread_self){
        strncpy(debug_buffer_thread_name, name, 16);
        debug_buffer_thread_name[15] = '\0';
        //assert(pk_trusted_tls.init);
        //assert(pk_trusted_tls.tid == thread);
        ////assert(pk_trusted_tls.thread_name_debug == NULL);
        //pk_trusted_tls.thread_name_debug = name;
    }
    //assert(pthread_setname_np(thread, name) == 0);
    //pthread_getname_np(thread, debug_buffer_thread_name, sizeof(debug_buffer_thread_name));
}
#endif /* RELEASE */
//------------------------------------------------------------------------------

#define __PREPEND_TO_DEBUG_BUFFER(MESSAGE, ...) \
    do { \
        if(!debug_buffer_ptr){\
            debug_buffer_ptr = debug_buffer; /*initialize on first use*/ \
        } \
        debug_buffer_ptr += snprintf(debug_buffer_ptr, sizeof(debug_buffer) - (size_t)((uintptr_t)debug_buffer_ptr - (uintptr_t)debug_buffer), MESSAGE, ##__VA_ARGS__); \
        assert((uintptr_t)debug_buffer_ptr - (uintptr_t)debug_buffer < sizeof(debug_buffer)); \
    } while (0)

#define HELPER(FD, MESSAGE, ...) \
    do { \
        __PREPEND_TO_DEBUG_BUFFER(MESSAGE, ##__VA_ARGS__); \
        write(FD, debug_buffer, (size_t)((uintptr_t)debug_buffer_ptr - (uintptr_t)debug_buffer)); \
        debug_buffer_ptr = debug_buffer; /* reset ptr*/ \
    } while (0)

//------------------------------------------------------------------------------

#ifdef DEBUG_TIME
extern uint64_t _time;
#define DEBUG_TIME_BEFORE_PRINT  uint64_t now = RDTSC();
#define DEBUG_TIME_AFTER_PRINT   do { \
        if (strcmp(__FILE__, "sf/sf_nested.c") == 0) \
            __PREPEND_TO_DEBUG_BUFFER(COLOR_MAGENTA "DEBUG_TIME %10zu %25s %4d %s\n" COLOR_RESET, now - _time, __FILE__, __LINE__, __func__); \
        _time = RDTSC(); \
    } while (0);

#else /* DEBUG_TIME */
#define DEBUG_TIME_BEFORE_PRINT
#define DEBUG_TIME_AFTER_PRINT
#endif /* DEBUG_TIME */

//------------------------------------------------------------------------------

#ifdef RELEASE
#define PREPEND_TO_DEBUG_BUFFER(MESSAGE, ...) \
    do { \
        DEBUG_TIME_BEFORE_PRINT \
        DEBUG_TIME_AFTER_PRINT \
    } while (0)
#else /* RELEASE */
#define PREPEND_TO_DEBUG_BUFFER(MESSAGE, ...) \
    do { \
        DEBUG_TIME_BEFORE_PRINT \
        __PREPEND_TO_DEBUG_BUFFER(COLOR_GREEN MESSAGE COLOR_RESET, ##__VA_ARGS__); \
        DEBUG_TIME_AFTER_PRINT \
    } while (0)
#endif /* RELEASE */

//------------------------------------------------------------------------------

//#define _DBG_TID_FMT "%5lu %6s: "
//#define _DBG_TID (unsigned long)getpid(), THREADNAME()
//#define _DBG_TID_FMT "0x%lx %6s: "
//#define _DBG_TID (pthread_self()>>12), THREADNAME()
#define _DBG_TID_FMT "%6lu %6s: "
#define _DBG_TID ({ unsigned long pid = &debug_pid ? debug_pid : 0; if (&debug_pid && !debug_pid /* we had a fork */){debug_pid = pid = getpid();} pid; }), THREADNAME()

#ifdef DONTPRINTANYTHING
#define ERROR_FAIL2(MESSAGE, ...) do { exit(EXIT_FAILURE); } while (0)
#define ERROR_FAIL(MESSAGE, ...)  do { exit(EXIT_FAILURE); } while (0)
#define ERROR(MESSAGE, ...)       do { ; } while (0)
#define WARNING(MESSAGE, ...)     do { ; } while (0)
#define DEBUG_MPK(MESSAGE, ...)   do { ; } while (0)
#define DEBUG_LOCK(MESSAGE, ...)  do { ; } while (0)
#define DEBUG_SF(MESSAGE, ...)    do { ; } while (0)
#define FLUSH_DEBUG_BUFFER()      do { ; } while (0)
#else /* DONTPRINTANYTHING */
#define FLUSH_DEBUG_BUFFER()      do { HELPER(STDERR, "%s", ""); } while (0)
#define ERROR_FAIL2(MESSAGE, ...) do { HELPER(STDERR, COLOR_RED    _DBG_TID_FMT "%s:%d: " MESSAGE COLOR_RESET "\n", _DBG_TID, __FILE__, __LINE__, ##__VA_ARGS__); if(errno){perror(NULL);} exit(EXIT_FAILURE); } while (0)
#define ERROR_FAIL(MESSAGE, ...)  do { HELPER(STDERR, COLOR_RED    _DBG_TID_FMT "%s: "    MESSAGE COLOR_RESET "\n", _DBG_TID, __func__,           ##__VA_ARGS__); if(errno){perror(NULL);} exit(EXIT_FAILURE); } while (0)
#define ERROR(MESSAGE, ...)       do { HELPER(STDERR, COLOR_RED    _DBG_TID_FMT "%s: "    MESSAGE COLOR_RESET "\n", _DBG_TID, __func__,           ##__VA_ARGS__); if(errno){perror(NULL);} } while (0)
#define WARNING(MESSAGE, ...)     do { HELPER(STDERR, COLOR_YELLOW _DBG_TID_FMT "%s: "    MESSAGE COLOR_RESET "\n", _DBG_TID, __func__,           ##__VA_ARGS__); } while (0)
#define DEBUG_MPK(MESSAGE, ...)   do { HELPER(STDERR, COLOR_CYAN   _DBG_TID_FMT "%s: "    MESSAGE COLOR_RESET "\n", _DBG_TID, __func__,           ##__VA_ARGS__); } while (0)
#define DEBUG_LOCK(MESSAGE, ...)  do { HELPER(STDERR, COLOR_CYAN   _DBG_TID_FMT "%s: "    MESSAGE COLOR_RESET "\n", _DBG_TID, __func__,           ##__VA_ARGS__); } while (0)

#define DEBUG_SF(MESSAGE, ...)    do { HELPER(STDERR, COLOR_GREEN  _DBG_TID_FMT "%s: "    MESSAGE COLOR_RESET "\n", _DBG_TID, __func__,           ##__VA_ARGS__); } while (0)
#endif /* DONTPRINTANYTHING */

#define FPRINTF(FILE, MESSAGE, ...) do { HELPER(fileno(FILE), MESSAGE, ##__VA_ARGS__); } while (0)

//#undef HELPER
//#undef __PREPEND_TO_DEBUG_BUFFER

//------------------------------------------------------------------------------
#if !defined(DEBUG_LOCKING)
    #ifdef DEBUG_LOCK
        #undef DEBUG_LOCK
        #define DEBUG_LOCK(MESSAGE, ...)
    #endif
#endif
//------------------------------------------------------------------------------
#ifdef RELEASE
    #ifdef DEBUG_MPK
        #undef DEBUG_MPK
        #define DEBUG_MPK(MESSAGE, ...)
    #endif
    #ifdef DEBUG_LOCK
        #undef DEBUG_LOCK
        #define DEBUG_LOCK(MESSAGE, ...)
    #endif
    #undef DEBUG_SF
    #define DEBUG_SF(MESSAGE, ...)

    #define assert_ifdebug(EXPRESSION)

    #ifdef ADDITIONAL_DEBUG_CHECKS
        #undef ADDITIONAL_DEBUG_CHECKS
    #endif /* ADDITIONAL_DEBUG_CHECKS */

    #ifdef DEBUG__CSR
        #undef DEBUG__CSR
    #endif /* DEBUG__CSR */

    #undef FLUSH_DEBUG_BUFFER
    #define FLUSH_DEBUG_BUFFER()


#else /* RELEASE */

    //#ifdef TIMING
    //    #error "timing non-release is not advised"
    //#endif /* TIMING */

    #define assert_ifdebug(EXPRESSION) assert(EXPRESSION)
#endif /* RELEASE */


// if timing and release: also suppress warnings
#ifdef RELEASE
#if defined(TIMING) || defined(SF_TIMING)
    #undef WARNING
    #define WARNING(MESSAGE, ...)
#endif
#endif /* RELEASE */

//------------------------------------------------------------------------------
static inline void PRINT_STACK(char* name, int size, const uint64_t * stack){
    for (int i = size-1; i >= 0; i--) {
        uint64_t word = *(stack+i);
        printf("%s[%4d] = %8zx = %zu\n", name, i, word, word);
    }
    puts("");
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

static inline void print_maps() {
    #ifndef RELEASE
    DEBUG_MPK("print_maps()");
    #ifndef PROXYKERNEL
    char line[2048];
    FILE * fp;
    // print maps, including protection keys
    DEBUG_MPK("print_maps() smaps");
    fp = fopen("/proc/self/smaps", "r");
    if(fp == NULL){
        ERROR_FAIL("Failed to fopen /proc/self/smaps");
    }
    while (fgets(line, 2048, fp) != NULL) {
        if (strstr(line, "-") != NULL
         || (strstr(line, "ProtectionKey") != NULL && strstr(line, "ProtectionKey:         0") == NULL)
         //|| strstr(line, "Size") == line
        ) {
            FPRINTF(stderr, "%s", line);
        }
    }
    fclose(fp);
    #endif // !PROXYKERNEL

    #endif // !RELEASE
}

//------------------------------------------------------------------------------

#define sprintf_and_malloc(MESSAGE, ...) ({ \
    char * buffer = NULL; \
    int len = snprintf(NULL, 0, MESSAGE, ##__VA_ARGS__) + 1; \
    buffer = malloc((size_t)len); \
    sprintf(buffer, MESSAGE, ##__VA_ARGS__); \
    buffer; \
})

//------------------------------------------------------------------------------
#define assert_warn(expression) do { \
    if(!(expression)) { \
        WARNING("assertion failed: %s", #expression); \
    } \
} while (0)

//------------------------------------------------------------------------------

// for printing debug messages whenever CSRs are used
#ifdef DEBUG__CSR
    #define DEBUG_CSR DEBUG_MPK
    #define IFDEBUG_CSR(CODE) CODE
#else
    #define DEBUG_CSR(MESSAGE, ...)
    #define IFDEBUG_CSR(CODE)
#endif

//------------------------------------------------------------------------------
#ifdef __riscv
    #ifdef TIMING_RDINSTRET
        __attribute__((always_inline)) static inline uint64_t RDTSC() {
            uint64_t res;
            __asm__ volatile ("fence.i");
            __asm__ volatile ("rdinstret %0": "=r" (res));
            __asm__ volatile ("fence.i");
            return res;
        }
    #else
        __attribute__((always_inline)) static inline uint64_t RDTSC() {
            uint64_t res;
            //__asm__ volatile ("fence.i");
            __asm__ volatile ("rdcycle %0": "=r" (res));
            //__asm__ volatile ("fence.i");
            return res;
        }
    #endif
#else // x86
    __attribute__((always_inline)) static inline uint64_t RDTSC() {
        uint64_t a, d;
        //__asm__ volatile ("mfence");
        __asm__ volatile ("lfence");
        __asm__ volatile ("rdtsc" : "=a" (a), "=d" (d));
        a = (d<<32) | a;
        __asm__ volatile ("lfence");
        //__asm__ volatile ("mfence");
        return a;
    }
#endif // __riscv/x86

//------------------------------------------------------------------------------

#define C_STATIC_ASSERT(test) typedef char assertion_on_mystruct[( !!(test) )*2-1 ]

//------------------------------------------------------------------------------
#ifdef TIMING
    //#ifndef RELEASE
    //    #error "timing with debug checks is not advised"
    //#endif /* RELEASE */

    //#ifdef ADDITIONAL_DEBUG_CHECKS
    //    #error "timing with debug checks is not advised"
    //#endif /* ADDITIONAL_DEBUG_CHECKS */

    //#ifdef DEBUG__CSR
    //    #error "timing with debug checks is not advised"
    //#endif /* DEBUG__CSR */

    //old: 1 table for all benchmarks
    //extern size_t timing_values_index;
    //typedef struct {
    //    const char * name;
    //    uint64_t time;
    //} _timing;
    //#define NUM_TIMING_VALUES 64 //should be power of two
    //#define TIME_LOG(NAME,VAL) do { timing_values[timing_values_index].name = NAME; timing_values[timing_values_index].time = VAL; timing_values_index = (timing_values_index + 1) % NUM_TIMING_VALUES; } while (0)
    //#define TIME_START(NAME) uint64_t _time_##NAME = RDTSC();
    //#define TIME_STOP(NAME)  do { _time_##NAME = RDTSC() - _time_##NAME; TIME_LOG(#NAME,_time_##NAME); /*FPRINTF(stderr, COLOR_MAGENTA "\nTIME(" #NAME ") = %lu" COLOR_RESET "\n\n", _time_##NAME);*/ } while (0)

    extern uint64_t timing_min;
    extern uint64_t timing_tmp;
    //Assertion so that we dont accidentally time things that are timing things themselves
    #define TIME_START(x) if ((x) == 1) { assert(timing_tmp == 0); timing_tmp = RDTSC(); }
    #define TIME_STOP(x)  if ((x) == 1) { timing_tmp = RDTSC() - timing_tmp; if(timing_tmp < timing_min ) { timing_min = timing_tmp; } assert(timing_tmp != 0); timing_tmp = 0; }

    #ifndef TIMING_HANDLER_C
    #define TIMING_HANDLER_C 0
    #else
    #define TIMING_HANDLER_C_TYPE TYPE_RET
    #endif

    typedef enum {
        TIMING_SIMPLE_API_CALL = 0,
        TIMING_ECALL_TEST_ARGS,
        TIMING_ECALL_SAVE_FRAME_OVERHEAD,
        TIMING_TEST_ARGS,
        TIMING_NESTING,
        TIMING_ECALL_TEST3_TIME_COMPLETE,
        TIMING_ECALL_TO_INSIDE,
        TIMING_INSIDE_ECALL_TO_RETURN,
        TIMING_MPROTECT,
        TIMING_GETPID,
        TIMING_INTERPOSE_GETPID,
        TIMING_CLOSE,
        TIMING_PKRU,
        TIMING_RDTSC,
        TIMING_T_MAX //must be last line with highest number
    } timing_index;

    __attribute__((always_inline)) static inline char * TIMING_INDEX_TO_STR(timing_index idx) {
        switch (idx)
        {
            #define CASE(x) case x:           return ((char*)#x) + 7; break; /* +7 to cut away "TIMING_" */
            CASE(TIMING_SIMPLE_API_CALL)
            CASE(TIMING_ECALL_TEST_ARGS)
            CASE(TIMING_TEST_ARGS)
            CASE(TIMING_ECALL_SAVE_FRAME_OVERHEAD)
            CASE(TIMING_NESTING)
            CASE(TIMING_ECALL_TEST3_TIME_COMPLETE)
            CASE(TIMING_ECALL_TO_INSIDE)
            CASE(TIMING_INSIDE_ECALL_TO_RETURN)
            CASE(TIMING_MPROTECT)
            CASE(TIMING_GETPID)
            CASE(TIMING_INTERPOSE_GETPID)
            CASE(TIMING_CLOSE)
            CASE(TIMING_PKRU)
            CASE(TIMING_RDTSC)
            #undef CASE
            default: break;
        }
        assert(0);
        return NULL;
    }

    #define NUM_TESTRUNS (1000)
    #define NUM_NESTING_LEVEL 10

    #ifdef TIMING_MEASURE_MINIMUM
    extern uint64_t timing_values[TIMING_T_MAX];
    __attribute__((always_inline)) static inline void TIME_LOG(timing_index idx, uint64_t value) {
        #ifdef TIMING
            assert(timing_tmp == 0); // in case the other timing thing runs
            if (timing_values[idx] == 0 || value < timing_values[idx]){
                timing_values[idx] = value;
            }
        #endif
    }
    #else // TIMING_MEASURE_MINIMUM
    extern uint64_t timing_values[TIMING_T_MAX][NUM_TESTRUNS];
    __attribute__((always_inline)) static inline void TIME_LOG(timing_index idx, size_t testrun, uint64_t value) {
        #ifdef TIMING
            assert(timing_tmp == 0); // in case the other timing thing runs
            assert(testrun < NUM_TESTRUNS);
            timing_values[idx][testrun] = value;
        #endif
    }
    #endif // TIMING_MEASURE_MINIMUM
#endif // TIMING

#ifdef __cplusplus
}
#endif

#endif // __ASSEMBLY__
