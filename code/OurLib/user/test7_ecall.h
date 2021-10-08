#pragma once

#include "test_ecalls.h"

#ifndef __ASSEMBLY__

#include <stdint.h>
#include <pk.h>

extern void ecall_test7(int *protected);
extern int  ecall_register_test7(int did);

extern void ecall_test7_nested(bool localstorage_filters);
extern int  ecall_register_test7_nested(int did);

#endif // __ASSEMBLY__
