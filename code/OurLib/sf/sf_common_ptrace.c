#include "common_ptrace.h"
#include "pk.h"

PK_DATA tracee_t tracees[NUM_THREADS];
PK_DATA int tracees_count;
PK_DATA size_t arch_xstate_size;