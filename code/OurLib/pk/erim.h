#pragma once
#include <stdint.h>

//erim_scanMemForWRPKRUXRSTOR taken from https://github.com/vahldiek/erim/blob/master/src/erim/erim.c

#define uint8ptr(ptr) ((uint8_t *)ptr)
#define INST_LEN_WRPKRU_AND_XRSTOR 3

#define erim_isWRPKRU(ptr)				\
  ((uint8ptr(ptr)[0] == 0x0f && uint8ptr(ptr)[1] == 0x01	\
   && uint8ptr(ptr)[2] == 0xef)?			\
  1 : 0)

#define erim_isXRSTOR(ptr) \
   ((uint8ptr(ptr)[0] == 0x0f && uint8ptr(ptr)[1] == 0xae \
    && (uint8ptr(ptr)[2] & 0xC0) != 0xC0 \
    && (uint8ptr(ptr)[2] & 0x38) == 0x28) ? 1 : 0)

//NOTE: returns -1 if nothing was found, else position
static unsigned long long _erim_scanMemForWRPKRUXRSTOR(char * mem_start, unsigned long length)
{
  uint8_t* ptr = (uint8_t*)mem_start;
  unsigned int it = 0;
  unsigned long long ret = -1; //setting to -1 to distinguish sequences at position 0
  for(it=0; it < length; it++) {
    if(erim_isWRPKRU(&ptr[it])) {
      ret = it;break;
    }
    if(erim_isXRSTOR(&ptr[it])) {
      ret = it; break;
    }
  }
  return ret;
}
