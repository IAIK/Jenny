#pragma once
#include "pk_defs.h"
#include <sys/syscall.h>

int _register_bpf_type(int type);

FORCE_INLINE int _seccomp(unsigned int op, unsigned int flags, void *args)
{
    errno = 0;
    return syscall(__NR_seccomp, op, flags, args);
}
