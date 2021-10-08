#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/syscall.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
//~ #include <linux/entry-common.h>

#include "sysfilter.h"
//#include "secure_monitor.h"

MODULE_AUTHOR("Michael Schwarz, Samuel Weiser, David Schrammel");
MODULE_DESCRIPTION("Filter syscalls");
MODULE_LICENSE("GPL");

static inline void write_cr0_direct(unsigned long val)
{
  unsigned long __force_order;
  asm volatile("mov %0,%%cr0": "+r" (val), "+m" (__force_order));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && CONFIG_X86_64
#define REGS_DEFINES const struct pt_regs* regs
#define REGS regs
#define SYSNO regs->orig_ax
#else
#define REGS_DEFINES long unsigned int a, long unsigned int b, long unsigned int c, long unsigned int d, long unsigned int e, long unsigned int f
#define REGS a, b, c, d, e, f
#define SYSNO ???
#error "Old linux does not provide us with syscall number"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define from_user raw_copy_from_user
#define to_user raw_copy_to_user
#else
#define from_user copy_from_user
#define to_user copy_to_user
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_KALLSYMS_LOOKUP 1
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_func;
#define kallsyms_lookup_name kallsyms_lookup_name_func

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

#ifdef DEBUG
#define DEBUG_KERN(...) printk(__VA_ARGS__)
#else
#define DEBUG_KERN(...) do {} while (0)
#endif

#define MOD_INFO "[sysfilter-module] "
#define PKEY_DEFAULT 0x55555554UL

#define SYSCALL_SYSFILTER_ACTIVE        30

static bool device_busy = false;
static int pid_filter = 0;
static int has_pke = 0;
static int pkey = PKEY_DEFAULT;
static uint32_t pkru_init_value = 0;
static int kill_on_violation = 0;
static uintptr_t monitor = 0;

static void unhook_all(void);

static void reset_all(void) {
	pid_filter = 0;
	pkey = PKEY_DEFAULT;
	kill_on_violation = 0;
	monitor = 0;
	unhook_all();
}

// ---------------------------------------------------------------------------
static int device_open(struct inode *inode, struct file *file) {
  /* Check if device is busy */
  if (device_busy == true) {
    return -EBUSY;
  }

  /* Lock module */
  try_module_get(THIS_MODULE);

  device_busy = true;

  return 0;
}

// ---------------------------------------------------------------------------
static int device_release(struct inode *inode, struct file *file) {
  /* Unlock module */
  device_busy = false;

  module_put(THIS_MODULE);

  return 0;
}

// ---------------------------------------------------------------------------
static sys_call_ptr_t old_sys_call_table[__NR_syscall_max];
static sys_call_ptr_t* syscall_tbl;

// ---------------------------------------------------------------------------
static int readkey(void) {
    size_t key = 0;
    if(has_pke) {
        asm volatile(
            "RDPKRU\n"
            "mov %%rax, %0\n"
            : "=r"(key) : "a"(0), "c"(0), "d"(0) : "memory");
    } else {
        key = pkey;
    }
    return (key & 0xffffffff);
}

// ---------------------------------------------------------------------------
static long hook_generic(REGS_DEFINES) {
    int pid = task_tgid_nr(current);
    int sys_nr = SYSNO;
    uintptr_t *rcx;
    uintptr_t* ip;
    long retval = 0;
    struct task_struct * task_child;

    // pid == pid_filter --> we are parent who installed filter
    //int filterme = pid_filter && (pid == pid_filter || test_ti_thread_flag(current_thread_info(), SYSCALL_SYSFILTER_ACTIVE));
    int filter_flag = test_ti_thread_flag(current_thread_info(), SYSCALL_SYSFILTER_ACTIVE);
    int filterme = filter_flag;
    if (filterme) {
        DEBUG_KERN(KERN_INFO MOD_INFO "hook_generic sys_nr: %3d, PID: %d, pid_filter: %d, filter_flag: %d\n", sys_nr, pid, pid_filter, filter_flag);
        int k = readkey();
        if (k & SYSFILTER_DELEGATE_MASK) {
            DEBUG_KERN(KERN_INFO MOD_INFO "Intercepting syscall %3d (PID: %d)\n", sys_nr, pid);
            if(kill_on_violation) {
                printk(KERN_INFO MOD_INFO "Killing program\n");
                kill_pid(find_vpid(pid), 2, 1);
                reset_all();
                return -1;
            }
            if (monitor) {
                if (!access_ok(monitor, 16)) printk(KERN_WARNING MOD_INFO "monitor not accessible");
                DEBUG_KERN(KERN_INFO MOD_INFO "Delegating to secure syscall monitor (sys: %zd, return ip: %zx)\n", regs->orig_ax, regs->ip);
                rcx = (size_t*)&(regs->cx);
                ip = (uintptr_t*)&(regs->ip);
                *rcx = *ip;            // save instruction following SYSCALL in RCX
                *ip = monitor;         // delegate ip to monitor
            }
            return regs->orig_ax;
        } else {
            DEBUG_KERN(KERN_INFO MOD_INFO "Allowing syscall %3d (PID: %d)\n", sys_nr, pid);
        }
    }

    retval = old_sys_call_table[sys_nr](REGS);
    if (filterme) {
        switch (sys_nr) {
            case __NR_vfork:
            case __NR_fork:
            case __NR_clone:
            case __NR_clone3:
            {
                DEBUG_KERN(KERN_INFO MOD_INFO "We got a clone. child pid = %ld\n", retval);
                // child has forked, give it the sysfilter flag
                // NOTE: all filtered processes have the same set of filtered syscalls (for now)
                //task_child = find_task_by_vpid(find_vpid(retval), PIDTYPE_PID);
                task_child = pid_task(find_vpid(retval), PIDTYPE_PID);
                if (NULL == task_child) {
                    printk(KERN_ALERT MOD_INFO "Unable to retrieve cloned child, pid = %ld\n", retval);
                }
                set_ti_thread_flag(task_thread_info(task_child), SYSCALL_SYSFILTER_ACTIVE);
                break;
            }
            default:
                break;
        }
    } 
    
    return retval;
}

// ---------------------------------------------------------------------------
static void hook_syscall(int nr, sys_call_ptr_t hook) {
    if (nr < 0 || nr >= __NR_syscall_max) {
        printk(KERN_ALERT MOD_INFO "syscall %d outside valid range\n", nr);
        return;
    }
    // unprotect syscall table
    write_cr0_direct(read_cr0() & ~0x10000);
    printk(KERN_INFO MOD_INFO "Hooking syscall %d\n", nr);
    syscall_tbl[nr] = hook;
    write_cr0_direct(read_cr0() | 0x10000);
}

// ---------------------------------------------------------------------------
static void unhook_syscall(int nr) {
    if (nr < 0 || nr >= __NR_syscall_max) {
        printk(KERN_ALERT MOD_INFO "syscall %d outside valid range\n", nr);
        return;
    }
    // unprotect syscall table
    write_cr0_direct(read_cr0() & ~0x10000);
    printk(KERN_INFO MOD_INFO "Unhooking syscall %d\n", nr);
    syscall_tbl[nr] = old_sys_call_table[nr];
    write_cr0_direct(read_cr0() | 0x10000);
}

// ---------------------------------------------------------------------------
static void unhook_all(void) {
  int i;
  // restore old syscall table
  printk(KERN_INFO MOD_INFO "Unhooking all syscalls\n");
  write_cr0_direct(read_cr0() & ~0x10000);
  for(i = 0; i < __NR_syscall_max; i++) {
      syscall_tbl[i] = old_sys_call_table[i];
  }
  write_cr0_direct(read_cr0() | 0x10000);
}

// ---------------------------------------------------------------------------
static long device_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param) {
  int pid = task_tgid_nr(current);
  struct task_struct * task_owner = NULL;
  if (pid_filter) {
    task_owner = pid_task(find_vpid(pid_filter), PIDTYPE_PID);
    if (!task_owner) {
      printk(KERN_WARNING MOD_INFO "Previous parent %d has died somehow. Cleaning up now\n", pid_filter);
      reset_all();
    }
  }

  switch (ioctl_num) {
    case SYSFILTER_IOCTL_CMD_BLOCK:
    case SYSFILTER_IOCTL_CMD_UNBLOCK:
    case SYSFILTER_IOCTL_CMD_UNBLOCK_ALL:
    case SYSFILTER_IOCTL_CMD_PID:
    case SYSFILTER_IOCTL_CMD_WRITEKEY:
    case SYSFILTER_IOCTL_CMD_READKEY:
    case SYSFILTER_IOCTL_CMD_KILL_ON_VIOLATION:
    case SYSFILTER_IOCTL_CMD_REGISTER_MONITOR:
    {
        if (pid_filter && pid_filter != pid) {
            // Only the parent is allowed to change filter
            printk(KERN_WARNING MOD_INFO "Locked by PID %d\n", pid_filter);
            return -1;
        }
        int k = readkey();
        if ((k & SYSFILTER_DELEGATE_MASK)) {
            printk(KERN_WARNING MOD_INFO "Locked by monitor\n");
            return -1;
        }
        break;
    }
    default:
        printk(KERN_WARNING MOD_INFO "Unhandled ioctl event %d", ioctl_num);
        return -1;
    }

  switch (ioctl_num) {
    case SYSFILTER_IOCTL_CMD_BLOCK:
    {
        hook_syscall(ioctl_param, hook_generic);
        return 0;
    }
    case SYSFILTER_IOCTL_CMD_UNBLOCK:
    {
        unhook_syscall(ioctl_param);
        return 0;
    }
    case SYSFILTER_IOCTL_CMD_UNBLOCK_ALL:
    {
        unhook_all();
        return 0;
    }
    case SYSFILTER_IOCTL_CMD_PID:
    {
        reset_all();
        pid_filter = ioctl_param;
        if(pid_filter) {
            printk(KERN_INFO MOD_INFO "Setting SYSCALL_SYSFILTER_ACTIVE flag for pid %d\n", pid_filter);
            set_ti_thread_flag(current_thread_info(), SYSCALL_SYSFILTER_ACTIVE);
        }
        return 0;
    }
    case SYSFILTER_IOCTL_CMD_WRITEKEY:
    {
        pkey = ioctl_param;
        return 0;
    }
    case SYSFILTER_IOCTL_CMD_READKEY:
    {
        return pkey;
    }
    case SYSFILTER_IOCTL_CMD_KILL_ON_VIOLATION:
    {
        kill_on_violation = ioctl_param;
        return 0;
    }
    case SYSFILTER_IOCTL_CMD_REGISTER_MONITOR:
    {
        monitor = (uintptr_t)ioctl_param;
        return 0;
    }
    default:
        return -1;
  }

  return 0;
}

// ---------------------------------------------------------------------------
static struct file_operations f_ops = {.unlocked_ioctl = device_ioctl,
                                       .open = device_open,
                                       .release = device_release};

// ---------------------------------------------------------------------------
static struct miscdevice misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = SYSFILTER_DEVICE_NAME,
    .fops = &f_ops,
    .mode = S_IRWXUGO,
};

// ---------------------------------------------------------------------------
int init_module(void) {
  int r, i;

#ifdef KPROBE_KALLSYMS_LOOKUP
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    if(!unlikely(kallsyms_lookup_name)) {
      pr_alert("Could not retrieve kallsyms_lookup_name address\n");
      return -ENXIO;
    }
#endif

  // check for PKE
  has_pke = !!(native_read_cr4() & (1ull << 22));
  printk(KERN_INFO MOD_INFO "PKE: %d\n", has_pke);

  if(has_pke) {
    // get initial pkru
      uint32_t* pkru_init = (uint32_t*)kallsyms_lookup_name("init_pkru_value");
      if(pkru_init) {
        pkru_init_value = *pkru_init;
      }
  }

  // register device
  r = misc_register(&misc_dev);
  if (r != 0) {
    printk(KERN_ALERT MOD_INFO "Failed registering device with %d\n", r);
    return 1;
  }

  syscall_tbl = (sys_call_ptr_t*)kallsyms_lookup_name("sys_call_table");
  printk(KERN_INFO MOD_INFO "Syscall table @ %zx\n", (size_t)syscall_tbl);

  // backup old sys call table
  for(i = 0; i < __NR_syscall_max; i++) {
      old_sys_call_table[i] = syscall_tbl[i];
  }

  printk(KERN_INFO MOD_INFO "Loaded.\n");

  return 0;
}

// ---------------------------------------------------------------------------
void cleanup_module(void) {
  reset_all();

  misc_deregister(&misc_dev);

  printk(KERN_INFO MOD_INFO "Removed.\n");
}
