#pragma once
/* See LICENSE file for license and copyright information */

#ifndef SYSFILTER_MODULE_H
#define SYSFILTER_MODULE_H

#include <stddef.h>

#define SYSFILTER_DEVICE_NAME "sysfilter"
#define SYSFILTER_DEVICE_PATH "/dev/" SYSFILTER_DEVICE_NAME

// Our monitor key has number 2 and is also used to decide for syscall delegation
// Default PKRU config: 0x55555554: monitor key is access-disabled but not write-disabled
// In monitor-mode PKRU config is 0, meaning that monitor is not write-disabled
// In domain-mode PKRU config has monitor's key access- and write-disabled
// Thus, we can use write-disabled bit to decide for delegation
#define PKEY_DISABLE_WRITE 0x2
#define SYSFILTER_MONITOR_KEY           2
#define SYSFILTER_DELEGATE_MASK   (PKEY_DISABLE_WRITE << (SYSFILTER_MONITOR_KEY*2))

#define SYSFILTER_IOCTL_MAGIC_NUMBER (long)0x1248

#define SYSFILTER_IOCTL_CMD_BLOCK             _IOR(SYSFILTER_IOCTL_MAGIC_NUMBER, 1, size_t)
#define SYSFILTER_IOCTL_CMD_PID               _IOR(SYSFILTER_IOCTL_MAGIC_NUMBER, 2, size_t)
#define SYSFILTER_IOCTL_CMD_UNBLOCK           _IOR(SYSFILTER_IOCTL_MAGIC_NUMBER, 3, size_t)
#define SYSFILTER_IOCTL_CMD_UNBLOCK_ALL       _IOR(SYSFILTER_IOCTL_MAGIC_NUMBER, 4, size_t)
#define SYSFILTER_IOCTL_CMD_WRITEKEY          _IOR(SYSFILTER_IOCTL_MAGIC_NUMBER, 5, size_t)
#define SYSFILTER_IOCTL_CMD_READKEY           _IOR(SYSFILTER_IOCTL_MAGIC_NUMBER, 6, size_t)
#define SYSFILTER_IOCTL_CMD_KILL_ON_VIOLATION _IOR(SYSFILTER_IOCTL_MAGIC_NUMBER, 7, size_t)
#define SYSFILTER_IOCTL_CMD_REGISTER_MONITOR  _IOR(SYSFILTER_IOCTL_MAGIC_NUMBER, 8, size_t)

#endif // SYSFILTER_MODULE_H
