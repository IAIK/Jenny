#pragma once

void timing_results(void);
void bench(void);
void bench_preinit(void);

uint64_t get_minimum(uint64_t* timings, size_t size);
uint64_t get_maximum(uint64_t* timings, size_t size);
int timing_cmp(const void * a, const void * b);
double get_average(uint64_t* timings, size_t size);
uint64_t get_median(uint64_t* timings, size_t size);
double get_variance(uint64_t* timings, size_t size, double avg);



#define ROUND_UP_TO_POWEROFTWO(number, multiple) ((number + multiple - 1) & -multiple)
#define WRITE_ALL_PAGES(addr, value, size) do{ \
    for (char* p = (char*)addr; p < (char*)addr+ROUND_UP_TO_POWEROFTWO(size, PAGESIZE); p=(char*)p+PAGESIZE) { \
        volatile uint64_t* pp = (volatile uint64_t*)p; \
        *pp = (uint64_t)p; \
        *pp = value; \
        {volatile uint64_t _tmp = *(volatile uint64_t*)p;} \
    } }while(0)
