#include "sf_internal.h"

//------------------------------------------------------------------------------
// Protected syscall table from STRACE
//------------------------------------------------------------------------------

#include "syscallent_base_nr.h" // STRACE

/* Define these shorthand notations to simplify the syscallent files. */
#include "sysent_shorthand_defs.h" // STRACE

// #define SEN(syscall_name) SEN_ ## syscall_name, SYS_FUNC_NAME(sys_ ## syscall_name)
// Initialize all fillters as UNSPECIFIED
#define SEN(syscall_name) SYSCALL_UNSPECIFIED

PK_DATA PK_API sysent_t sf_table[] = {
#include "syscallent.h" // STRACE
};
C_STATIC_ASSERT((sizeof(sf_table) / sizeof(sysent_t)) == NUM_MONITOR_FILTERS);

/* Now undef them since short defines cause wicked namespace pollution. */
#include "sysent_shorthand_undefs.h" // STRACE

//------------------------------------------------------------------------------

ssize_t _sf_write_results(int fd, const void *buf, size_t count)
{
    // write to fd inside of monitor to bypass any syscall filters
    DEBUG_SF("_sf_write_results(%d, %s, %zu)", fd, (const char *)buf, count);
    return write(fd, buf, count);
}
//------------------------------------------------------------------------------

void PK_CODE _sf_empty_filter(trace_info_t *ti) {
    DEBUG_FILTER();
}
//------------------------------------------------------------------------------





