#include "common_filters.h"
#include <sys/prctl.h>

#define SUID_DUMP_DISABLE 0

/*
    prctl PR_SET_DUMPABLE = SUID_DUMP_DISABLE. 
    * value is reset to /proc/sys/fs/suid_dumpable when:
        * process user/group ID changes             -> blocked in sf_base_filters_common.c
        * process filesystem user7group ID changes  -> blocked in sf_base_filters_common.c
        * execve ... (details in manpage)           -> blocked in sf_base_filters_common.c

    * (non-root) can no longer access /proc/[pid] if not dumpable.
        * not really a problem: if monitor needs /proc/self, it can simply set the process to dumpable (and prevent any other thread from doing syscalls during that time)
*/

void PK_CODE _sf_base_filters_prctl_init()
{

//~ #ifdef RELEASE
    //~ if (prctl(PR_SET_DUMPABLE, SUID_DUMP_DISABLE) != 0) {
        //~ ERROR_FAIL("could not enable self protection (failed to set PR_SET_DUMPABLE to 0)");
    //~ }
//~ #else
    //~ WARNING("Ignoring PR_SET_DUMPABLE in DEBUG mode to enable debugging in gdb");
//~ #endif
}
