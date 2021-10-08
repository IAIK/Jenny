#include "pk_defs.h"
#include "pk_debug.h"

__thread PK_API char debug_buffer[10*4096];
__thread PK_API char * debug_buffer_ptr;
__thread PK_API char debug_buffer_thread_name[4096];
  PK_API unsigned long* debug_buffer_process_private;

#ifdef DEBUG_TIME
uint64_t _time = 0;
#endif /* DEBUG_TIME */
