#include "sf.h"
#include "bench.h"
#include "bench_sf.h"
#include <unistd.h>
#include <math.h>


enum test_t {
    TEST_GETPID,
    TEST_OPEN,
    TEST_OPEN_WRITE_4,
    TEST_OPEN_WRITE_16,
    TEST_OPEN_WRITE_256,
    TEST_OPEN_WRITE_512,
    TEST_OPEN_WRITE_1024,
    TEST_OPEN_WRITE_2048,
    TEST_OPEN_WRITE_4096,
    NUM_TESTS // last element
};

static char * test_to_str(enum test_t nr){
    switch (nr)
    {
        case TEST_GETPID:            return "getpid"; break;
        case TEST_OPEN:              return "open"; break;
        case TEST_OPEN_WRITE_4:      return "open+write 4 bytes"; break;
        case TEST_OPEN_WRITE_16:     return "open+write 16 bytes"; break;
        case TEST_OPEN_WRITE_256:    return "open+write 256 bytes"; break;
        case TEST_OPEN_WRITE_512:    return "open+write 512 bytes"; break;
        case TEST_OPEN_WRITE_1024:   return "open+write 1024 bytes"; break;
        case TEST_OPEN_WRITE_2048:   return "open+write 2048 bytes"; break;
        case TEST_OPEN_WRITE_4096:   return "open+write 4096 bytes"; break;
        default:                     return "?"; break;
    }
}

#ifdef __x86_64__
//#define NUM_RUNS 10000
#define NUM_RUNS 100
#else
#define NUM_RUNS 100
#endif

#define NUM_INNER_RUNS 100


uint64_t timings[NUM_TESTS][NUM_RUNS] = {0,};
char TESTFILE[40] = {0,};


#ifdef RELEASE
#define DEBUG_BENCH(MESSAGE, ...)
#else
#define DEBUG_BENCH(MESSAGE, ...)   do { fprintf(stderr, MESSAGE, ##__VA_ARGS__); } while (0)
#endif

#define RUN_FILE_TEST(no, size) { \
    /* -1-th run is a warmup run */ \
    for (int run = -1; run < NUM_RUNS; run++) { \
        /* creating TESTFILE (a new one for all NUM_INNER_RUN tests) */ \
        fd = syscall(SYS_openat, AT_FDCWD, (long)TESTFILE, O_CREAT, 0777); \
        assert(fd > 0); \
        close(fd); \
        DEBUG_BENCH("doing test %s\n", test_to_str(no)); \
        uint64_t time = RDTSC(); \
        for (int i = 0; i < NUM_INNER_RUNS; i++) { \
            int fd = syscall(SYS_openat, AT_FDCWD, (long)TESTFILE, O_RDWR); \
            assert_ifdebug(fd > 0); \
            write(fd, buffer, size); \
            close(fd); \
        } \
        uint64_t timing = RDTSC() - time; \
        if (run >= 0) timings[no][run] = timing; \
        /* cleanup */ \
        unlinkat(AT_FDCWD, TESTFILE, 0); \
    } \
}

#define RUN_TEST(no, code) {\
    /* -1-th run is a warmup run */ \
    for (int run = -1; run < NUM_RUNS; run++) { \
        DEBUG_BENCH("doing test %s\n", test_to_str(no)); \
        uint64_t time = RDTSC(); \
        for (int i = 0; i < NUM_INNER_RUNS; i++) { \
            code \
        } \
        uint64_t timing = RDTSC() - time; \
        if (run >= 0) timings[no][run] = timing; \
    } \
}

static char * get_arch_str(){
    #ifdef __x86_64__
        #ifdef FAKE_MPK_REGISTER
            return "x86_64_pk";
        #else
            return "x86_64";
        #endif
    #else
        #ifdef PROXYKERNEL
            return "riscv-pk";
        #else
            return "riscv";
        #endif
    #endif
}

FILE *results_file;

void timing_results_sf()
{
    fprintf(stderr, "ARCH      = %s\n", get_arch_str());
    fprintf(stderr, "NUM_RUNS  = %d\n", NUM_RUNS);
    fprintf(stderr, "MECHANISM = %s\n", mechanism_str(sf_data.sf_mechanism_current));
    fprintf(stderr, "FILTER    = %s\n", filter_str(sf_data.sf_filter_current));

    fprintf(stderr, "%25s  %8s%8s%8s%10s%9s", "test_name", "min", "max", "med", "avg", "std");
    fprintf(stderr, "\n");
    FPRINTF_RESULTS(results_file, "syscall;time\n");

    for (size_t i = 0; i < 2 /*NUM_TESTS*/; i++) {
        fprintf(stderr, "%25s ", test_to_str(i));

        uint64_t maximum = 0;
        uint64_t minimum = INT64_MAX;
        uint64_t average = 0;
        for (int run = 0; run < NUM_RUNS; run++) {
            uint64_t timing = timings[i][run];
            maximum = maximum < timing ? timing : maximum;
            minimum = minimum > timing ? timing : minimum;
            average += timing;
            FPRINTF_RESULTS(results_file, "%s;%ld\n", test_to_str(i), timing);
        }
        average /= NUM_RUNS;
        uint64_t min = get_minimum(timings[i], NUM_RUNS);
        uint64_t max = get_maximum(timings[i], NUM_RUNS);
        uint64_t med = get_median(timings[i], NUM_RUNS);
        double   avg = get_average(timings[i], NUM_RUNS);
        double   var = get_variance(timings[i], NUM_RUNS, avg);
        double   std = sqrt(var);
        //fprintf(stderr, "%25ld ", average);
        fprintf(stderr, "  <%6zu >%6zu ~%6zu %9.2f+-%7.2f\n", min, max, med, avg, std);
    }
    //fclose(f);   // is not possible for e.g. FILTER=extended-monitor
}

void bench_sf_preinit()
{
    //write and clear the entire array to make sure it exists
    WRITE_ALL_PAGES(timings, 0x1234, sizeof(timings));
    WRITE_ALL_PAGES(timings, 0,      sizeof(timings));

    // open file before initialization of filters
    mkdir("results", 0777);
    errno = 0;

    char filename[PATH_MAX];
    char* mech = getenv("MECHANISM");
    char* filt = getenv("FILTER");
    assert(mech);
    assert(filt);
    sprintf(filename, "results/results_%s_%s_%s.csv", get_arch_str(), mech, filt);
    results_file = fopen(filename, "w");

    fprintf(stderr, "saving to %s\n", filename);
}

void bench_sf()
{
    #define TESTFOLDER "/tmp"
    uint64_t random = RDTSC();
    snprintf(TESTFILE, sizeof(TESTFILE), TESTFOLDER "/testfile-%zu.txt", random);

    //~ #define TESTFILE "/tmp/testfile.txt"
    const size_t BUFFER_SIZE = 4096;
    char* buffer = mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(MAP_FAILED != buffer);
    memset(buffer, 0xab, BUFFER_SIZE);

    RUN_TEST(TEST_GETPID, {
        syscall(SYS_getpid);
    })

    // creating / opening TESTFOLDER
    mkdir(TESTFOLDER, 0777);
    errno = 0;
    int fd;

    // -1-th run is a warmup run
    for (int run = -1; run < NUM_RUNS; run++) {
        uint64_t time = RDTSC();
        for (int i = 0; i < NUM_INNER_RUNS; i++) {
            fd = syscall(SYS_openat, AT_FDCWD, (long)TESTFOLDER, O_RDONLY);
        }
        uint64_t timing = RDTSC() - time;
        if (run >= 0) timings[TEST_OPEN][run] = timing;
        for (int i = 0; i < NUM_INNER_RUNS; i++) {
            close(fd - i);
        }
    }

}
