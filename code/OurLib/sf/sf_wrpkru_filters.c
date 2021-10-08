
/**
 * DLOPEN does (strace'd experiments/dlopen/main)
 *   open("./libtest.so", O_RDONLY|O_CLOEXEC) = 3
 *   read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0 \6\0\0\0\0\0\0"..., 832) = 832
 *   fstat(3, {st_mode=S_IFREG|0775, st_size=10496, ...}) = 0
 *   mmap(NULL, 2101304, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f0785aa5000
 *   mprotect(0x7f0785aa6000, 2093056, PROT_NONE) = 0
 *   mmap(0x7f0785ca5000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0) = 0x7f0785ca5000
 *   close(3)                                = 0
 *   mprotect(0x7f0785ca5000, 4096, PROT_READ) = 0
 *
 * We can safely assume that .text is always initially mmapped with PROT_EXEC. We do not need to handle cases
 * in which a PROT_WRITE mmap gets PROT_EXEC later via mprotect.
 */
 
/**
 * 1. _sanitize_path for /tmp/.donky/ Noone except monitor should be allowed access to it
 * 
 * 2. intercept open-like syscalls
 *    * internally store path alongside fd
 *
 * 3. intercept mmap
 *    * if fd a special file (shared mem, pseudo file, etc), disallow PROT_EXEC. This is abnormal behavior anyways
 *    * if PROT_EXEC
 *       - remove PROT_EXEC flag
 *       - if fd is a file, copy it to /tmp/.donky/, reopen another fd and substitute it in the mmap call
 *    * inside internal mapping table
 *       - store fd
 *       - store originally requested perms
 *       - everything is tainted as unchecked by default
 *
 * 4. intercept [pkey_]mprotect
 *    * if PROT_EXEC
 *       - remove PROT_EXEC flag
 *       - if fd-backed and fd is a special file (shared mem, pseudo file, etc) or it not in our /tmp/.donky/ list, fail with an error
 *       - store originally requested perms
 *    * if PROT_WRITE
 *       - taint it as unchecked
 *
 * 5. intercept segfaults
 *    * if access == READ --> segfault
 *    * if access == WRITE and original perms allow it, mprotect(READ|WRITE), taint it
 *    * if access == EXEC and original perms allow it:
 *       - if tainted as unchecked
 *         * scan current page
 *         * scan for cross-page dangerous instructions at both page boundaries
 *         * untaint
 *         * mprotect(READ|EXEC)
 */
