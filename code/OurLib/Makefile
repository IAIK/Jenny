# PLATFORM is one of (riscv, x86_64)
PLATFORM ?= x86_64
# SIM is one of ("", pk)
SIM?=
SHARED?=
UNSAFE_SIGNALS?=
CCFLAGS?=
# To print object files and symbols during linking
#LDFLAGS?=-Wl,--print-map
LDFLAGS?=
LDLIBS?=
LDLIBS_MAIN?=
INSTALLDIR?=/usr/lib

# get path of this makefile
MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR := $(dir $(MKFILE_PATH))

# path of testroot lib (modified libc)
MODDED_LIBC     := $(abspath $(MKFILE_DIR)/../testroot/root)

# ------------------------------------------------------------------------------

LDLIBS+=-lpthread -ldl -lm
LDLIBS_MAIN+=-lrt -lpthread
CCFLAGS+=-DTLS_MISALIGNMENT_BUG

# ------------------------------------------------------------------------------

ifeq ($(DEBUG_TIME),1)
CCFLAGS+=-DDEBUG_TIME
endif

ifeq ($(RELEASE),1)
CCFLAGS+=-DRELEASE
endif

ifeq ($(TIMING),1)
CCFLAGS+=-DTIMING
LDLIBS+=-lm
endif

ifeq ($(SF_TIMING),1)
CCFLAGS+=-DSF_TIMING
LDLIBS+=-lm
endif

ifeq ($(CONSTRUCTOR),1)
CCFLAGS+=-DCONSTRUCTOR
endif

ifeq ($(ALLTESTS),1)
CCFLAGS+=-DALLTESTS
endif

ifeq ($(PRELOAD),1)
CCFLAGS+=-DCONSTRUCTOR
CCFLAGS+=-DDL_HOOKING
CCFLAGS+=-DDLU_HOOKING
#CCFLAGS+=-DDLU_HOOKING_SIGNAL
LDLIBS+=-ldl
export DO_LD_PRELOAD=$(CURDIR)/libpku.so:$(CURDIR)/libpk.so:$(CURDIR)/../testroot/root/lib/libc.so.6
endif

ifeq ($(UNSAFE_SIGNALS),1)
CCFLAGS+=-DUNSAFE_SIGNALS
endif

CCFLAGS+=$(CF)

ifeq ($(SHARED),1)
CCFLAGS+=-fPIC
CCFLAGS+=-fvisibility=hidden
CCFLAGS+=-DSHARED
LD_LIBRARY_PATH=$(CURDIR)
export LD_LIBRARY_PATH
endif

ifeq ($(FAKEMPK),1)
CCFLAGS+=-DFAKE_MPK_REGISTER
CCFLAGS+=-DFAKE_PKEY_SYSCALLS 
endif # FAKEMPK

ifeq ($(KERNEL_PATCH),1)
CCFLAGS+=-DSIGNAL_PKRU_KERNEL_PATCH
endif # KERNEL_PATCH

# ------------------------------------------------------------------------------


########################################################################
# RISC-V
########################################################################
ifeq ($(PLATFORM),riscv)

$(error RISCV currently not supported)

ifndef RISCV
$(error RISCV is not set)
endif

ifndef SDKBASE
$(error SDKBASE is not set)
endif

SDKBASE?=$(realpath ../../ariane-sdk)/

PREFIX=$(RISCV)/bin/riscv64-unknown-linux-gnu-
ARCH=arch/riscv

# compiler selection for platform
AR=$(PREFIX)gcc-ar
CC=$(PREFIX)gcc
LD=$(PREFIX)ld
OD=$(PREFIX)objdump
OC=$(PREFIX)objcopy
GDB=$(PREFIX)gdb

LDFLAGS+=-L$(RISCV)/riscv64-unknown-linux-gnu/lib64/lp64d \
         -L$(RISCV)/riscv64-unknown-linux-gnu/lib64 \
         -L$(RISCV)/riscv64-unknown-linux-gnu/lib

RUN=$(RISCV)/bin/spike
#RUNARGS=--isa=rv64imacn
RUNARGS=
DEBUGGER=$(RISCV)/bin/spike
#DEBUGARGS=--isa=rv64imacn -d
DEBUGARGS=-d

#CCFLAGS+=-mabi=lp64 -march=rv64imac
#CCFLAGS+=-mabi=lp64d -march=rv64imafdc

BUILD_DEPS=
CCFLAGS+=-DFAKE_TLS_SWAP -DSYSCALL_SANDBOXING
ifeq ($(SIM),pk)

CCFLAGS+=-DPROXYKERNEL #-DFAKE_PKEY_SYSCALLS
RUN_DEPS=
RUN_BIN=$(SDKBASE)/riscv-pk/build/pk $(MAIN)
DEBUG_BIN=$(RUN_BIN)
#LDFLAGS+=-static

else  # SIM=pk

CCFLAGS+=
RUN_DEPS=linux
RUN_BIN=$(SDKBASE)/bbl

endif # SIM=pk

#fvisibility=hidden might help aviding GOT stuff
CCFLAGS+=-fvisibility=hidden

endif # PLATFORM=riscv

########################################################################
# x86_64
########################################################################
ifeq ($(PLATFORM),x86_64)
PREFIX=

# compiler selection for platform
AR=$(PREFIX)gcc-ar
CC=$(PREFIX)clang
LD=$(PREFIX)ld
OD=$(PREFIX)objdump
OC=$(PREFIX)objcopy
GDB=$(PREFIX)gdb

ARCH=arch/x86_64
#CCFLAGS+=-Werror

ifeq ($(SIM),pk)

CCFLAGS+=-DFAKE_MPK_REGISTER
CCFLAGS+=-DFAKE_PKEY_SYSCALLS
CCFLAGS+=-DFAKE_TLS_SWAP

else # SIM

# Since we cannot build x86 hardware
CCFLAGS+=-DFAKE_TLS_SWAP

endif # SIM

# link to modified libc
# Note: we need the modified libc for indirect syscalls and for pthread_attr_setscope/create_thread
ifneq ($(SHARED),1)
BUILD_DEPS=testroot
#LDFLAGS+=-L../testroot/root/lib
LDFLAGS+=--sysroot=../testroot/root/
#LDFLAGS+=--sysroot=$(MODDED_LIBC)
else
# Make runtime linker also find libpk[u].so by specifying their abspath as rpath
LDFLAGS+=-Wl,-rpath=$(CURDIR)
# Make runtime linker use correct modded LIBC
LDFLAGS+=-Wl,-rpath=$(CURDIR)/../testroot/root/lib
# Enable full RELRO, which causes all got entries to be fetched ahead of time
# Otherwise, dynamic linker might try to write GOT entries which are protected
# with our read-only protection key
LDFLAGS+=-Wl,-z,relro,-z,now
endif

RUN_DEPS=
RUN=
RUNARGS=
RUN_BIN=
ifeq ($(PRELOAD),1)
RUN_BIN+=LD_PRELOAD=$(DO_LD_PRELOAD)
endif

# setarch needs "personality" syscall, which we block
#RUN_BIN+= setarch x86_64 --addr-no-randomize
RUN_BIN+= ./$(MAIN)
DEBUGGER=./gdbscreen.sh gdb
# we need to use --args for gdb to pass the filter mechanism ("--args" needs to be last)
DEBUGARGS=-x .gdb --args
DEBUG_BIN=./$(MAIN)
endif # PLATFORM=x86_64
## END OF x86_64 ###############################################################

# ------------------------------------------------------------------------------
ifndef ARCH
$(error Unknown platform $(PLATFORM))
endif
# ------------------------------------------------------------------------------
AWK=awk
LDSCRIPT=$(ARCH)/linker
# ------------------------------------------------------------------------------

ifeq ($(ASAN),1)
ifeq ($(SHARED),1)
CCFLAGS+=-fsanitize=address
LDFLAGS+=-fsanitize=address
else
$(error ASAN only works for SHARED=1)
endif
endif

# FLAGS FOR CC AND LD
include lib/strace/strace.mk
CCFLAGS+=-I. -Ipk -Isf -Isf/$(ARCH) -Ipk/$(ARCH) -Iuser -Iuser/$(ARCH) -I../kernel_module_syscall_hook -Ilib
#CCFLAGS+=-I../testroot/root/include
CFLAGS+=-std=gnu11
CXXFLAGS+=-std=c++11

# warnings:
CCFLAGS+=-Wall
#CCFLAGS+=-Wunused-parameter
#CCFLAGS+=-Wextra
#CCFLAGS+=-pedantic

# errors:
CCFLAGS+=-Werror
CCFLAGS+=-Wno-error=unused
CCFLAGS+=-Wno-error=volatile-register-var
CCFLAGS+=-Wno-error=array-bounds
CCFLAGS+=-Wno-error=address-of-packed-member
CCFLAGS+=-Wno-error=unused-variable

#~ CCFLAGS+=-Werror=shadow
#~ CCFLAGS+=-Werror=implicit-function-declaration
#~ CCFLAGS+=-Werror=pointer-arith
#~ CCFLAGS+=-Werror=format
#~ CCFLAGS+=-Werror=int-conversion
#~ CCFLAGS+=-Werror=incompatible-pointer-types
#~ CCFLAGS+=-Werror=ignored-qualifiers
#~ CCFLAGS+=-Werror=missing-field-initializers
#~ CCFLAGS+=-Werror=sign-compare

#~ CCFLAGS+=-Werror=sign-conversion
#~ CCFLAGS+=-Werror=pointer-sign

ifeq ($(CC),clang)
CCFLAGS+=-Werror=address-of-packed-member
CCFLAGS+=-Werror=unused-comparison
CCFLAGS+=-Werror=tautological-unsigned-zero-compare
CCFLAGS+=-Werror=tautological-unsigned-enum-zero-compare
CCFLAGS+=-Werror=signed-unsigned-wchar
else
CCFLAGS+=-Wno-error=unused-but-set-variable
CCFLAGS+=-Wno-error=restrict
endif

# misc
CCFLAGS+=-pthread
CCFLAGS+=-g
CCFLAGS+=-fPIC
#LDFLAGS+=-no-pie
#LDFLAGS+=-pie
#LDFLAGS+=-Wl,-z,relro

# optimizations
CCFLAGS+=-O3
#CCFLAGS+=-O0
#CCFLAGS+=-flto
#LDFLAGS+=-flto
#CCFLAGS+=-flto=thin
#LDFLAGS+=-flto=thin

# additional debug flags for our library
CCFLAGS+=-DADDITIONAL_DEBUG_CHECKS
CCFLAGS+=-DDEBUG__CSR

ifneq ($(SHARED),1)
# alternative to -static: sudo ln -s ${RISCV}/sysroot/lib/ld-linux-riscv64-lp64d.so.1 /lib
LDFLAGS+=-static
endif

# ------------------------------------------------------------------------------

PK_OBJ=pk/pk_handler_generic.o pk/pk_debug.o pk/$(ARCH)/pk_handler_c.o pk/$(ARCH)/pk_handler.o
PKU_OBJ=pk/pku_handler_generic.o pk/$(ARCH)/pku_handler_c.o pk/$(ARCH)/pku_handler.o pk/mprotect.o

SF_OBJ= sf/sf.o sf/sf_ptrace.o sf/sf_ptrace_seccomp.o sf/sf_ptrace_delegate.o sf/sf_common_ptrace.o sf/sf_wrpkru_filters.o sf/sf_nested.o sf/sf_seccomp_user.o sf/sf_common_base_filters.o sf/sf_base_filters_sanitization.o sf/sf_base_filters_open.o sf/sf_base_filters_prctl.o
SFU_OBJ=sf/sfu.o sf/sfu_ecall_wrapper.o sf/sfu_common_seccomp.o sf/sfu_ptrace.o sf/sfu_ptrace_seccomp.o sf/sfu_ptrace_delegate.o sf/sfu_nested.o sf/sfu_seccomp_user.o sf/sfu_seccomp.o sf/sfu_extended_filters.o

PK=pk.a
PKU=pku.a
SF=sf.a
SFU=sfu.a
PKSO=libpk.so
PKUSO=libpku.so
ifeq ($(SHARED),1)
MAIN=x.elf-shared
else
MAIN=x.elf
endif

# ------------------------------------------------------------------------------

.PHONY: all
all: $(MAIN)

USR_OBJ=main.o \
	user/$(ARCH)/tests.o \
	user/test_ecalls.o \
	user/test0.o \
	user/test1_api.o \
	user/$(ARCH)/test2.o user/$(ARCH)/test2_ecall.o \
	user/test3.o \
	user/test4_pthread.o \
	user/test5.o \
	user/test6.o \
	user/test7.o \
	user/test8.o \
	user/bench.o \
	user/bench_sf.o
USR=usr.a

$(LDSCRIPT).ld:
	mkdir -p $(dir $(LDSCRIPT).%)
	$(LD) --verbose > $@.tmp
	@./patch_ld.sh $@.tmp
	@mv $@.tmp $@

$(LDSCRIPT).lds:
	mkdir -p $(dir $(LDSCRIPT).%)
	$(LD) -shared --verbose > $@.tmp
	@./patch_ld.sh $@.tmp
	@mv $@.tmp $@

%.o: %.c
	$(CC) $(CFLAGS) $(CCFLAGS) -c $^ -o $@

%.o: %.cc
	$(CC) $(CXXFLAGS) $(CCFLAGS) -c $^ -o $@

%.o: %.S
	$(CC) $(CCFLAGS) -c $^ -o $@

$(PK): $(PK_OBJ)
	$(AR) -crs $@ $^

$(PKU): $(PKU_OBJ)
	$(AR) -crs $@ $^

$(SF): $(SF_OBJ)
	$(AR) -crs $@ $^

$(SFU): $(SFU_OBJ)
	$(AR) -crs $@ $^

$(PKSO): $(PK_OBJ) $(SF_OBJ)
	$(CC) -shared -o $@ $(LDFLAGS) $(CCFLAGS) $^ $(LDLIBS)

$(PKUSO): $(PKU_OBJ) $(SFU_OBJ) | $(PKSO)
	$(CC) -shared -o $@ $(LDFLAGS) $(CCFLAGS) $^ $(LDLIBS) -L. -lpk

$(USR): $(USR_OBJ)
	$(AR) -crs $@ $^
	# clang 7.0.0 workaround --remove-section .llvm_addrsig because of:
	# https://sourceware.org/bugzilla/show_bug.cgi?id=23788
	$(OC) --remove-section .llvm_addrsig --redefine-syms=rename_pk.lst $@

# We mis-use order-only prerequisites to use separate linker script ($|)
# from the object files ($^)
# We enclose all object files into --start-group/--end-group to avoid
# problems with the link order

ifeq ($(SHARED),1)

$(MAIN): $(USR) | $(PKSO) $(PKUSO)
	$(CC) -o $@ $(LDFLAGS) -Wl,--start-group $^ $(PKSO) $(PKUSO) -Wl,--end-group $(LDLIBS) $(LDLIBS_MAIN)

else

$(MAIN): $(USR) $(PK) $(PKU) $(SF) $(SFU) | $(LDSCRIPT).ld
	$(CC) -o $@ $(LDFLAGS) -Wl,-T $| -Wl,--start-group $^ -Wl,--end-group $(LDLIBS) $(LDLIBS_MAIN)

endif

# ------------------------------------------------------------------------------

.PHONY: testroot
testroot:
	make -C ../testroot all

.PHONY: testroot_with_clean
testroot_with_clean:
	make -C ../testroot clean all

.PHONY: debug
debug: $(BUILD_DEPS) $(MAIN)
	$(OD) -t $(MAIN) | grep '[ _]pk_\|ecall\|_debug' | awk '{print "until pc 0 "$$1" # "$$(NF)}' | sort -k6
	$(DEBUGGER) $(DEBUGARGS) $(DEBUG_BIN) $(MECHANISM)

.PHONY: run_deps
run_deps:  $(RUN_DEPS)

.PHONY: run
run: $(BUILD_DEPS) $(MAIN) $(RUN_DEPS)
	$(RUN) $(RUNARGS) $(RUN_BIN) $(MECHANISM)

.PHONY: run_quiet
run_quiet: $(BUILD_DEPS) $(MAIN) $(RUN_DEPS)
	$(RUN) $(RUNARGS) $(RUN_BIN) $(MECHANISM) 2>/dev/null

ifeq ($(SHARED),1)
out_files = $(PKSO) $(PKUSO)
else
out_files = $(PK) $(PKU)
endif
.PHONY: install
install: $(out_files)
	@echo "Installing '$^' into '$(INSTALLDIR)'"
	sudo cp -t '$(INSTALLDIR)' $^

.PHONY: clean
clean:
	rm -f --preserve-root $(PK_OBJ) $(PKU_OBJ) $(USR_OBJ) $(SF_OBJ) $(SFU_OBJ) $(PK) $(PKSO) $(PKU) $(PKUSO) $(SF) $(SFU) $(USR) $(LDSCRIPT).ld pk_stats.csv results.csv $(MAIN)
	sudo rm -f --preserve-root $(INSTALLDIR)/$(PK)
	sudo rm -f --preserve-root $(INSTALLDIR)/$(PKSO)
	sudo rm -f --preserve-root $(INSTALLDIR)/$(PKU)
	sudo rm -f --preserve-root $(INSTALLDIR)/$(PKUSO)

.PHONY: clean-all
clean-all: clean
	rm -f --preserve-root $(SDKBASE)/rootfs/$(MAIN) $(MAIN) core

benchmark_dependencies = $(BUILD_DEPS) _benchmark_dependencies install
.PHONY: _benchmark_dependencies
_benchmark_dependencies:
	make -C benchmarks/overalltiming
	make -C ../kernel_module_syscall_hook run_test || make -C ../kernel_module_syscall_hook clean load run_test
	make -C ../nginx_aux all test
	make -C ../lmbench

.PHONY: bench-x86-pk
bench-x86-pk: $(benchmark_dependencies)
	rm -rf --preserve-root results
	make PLATFORM=x86_64 RELEASE=1 TIMING=0 SIM=pk SF_TIMING=1 SHARED=1 clean all
	./run/bench-x86-pk.sh

.PHONY: bench-x86
bench-x86: $(benchmark_dependencies)
	rm -rf --preserve-root results
	make PLATFORM=x86_64 RELEASE=1 TIMING=0 SIM= SF_TIMING=1 SHARED=1 clean all
	./run/bench-x86.sh

.PHONY: app-bench-x86-pk
app-bench-x86-pk: $(benchmark_dependencies)
	make PLATFORM=x86_64 RELEASE=1 TIMING=0 SIM=pk CONSTRUCTOR=1 SHARED=1 PRELOAD=1 clean all
#	cd benchmarks && ./run_all.sh all

.PHONY: app-bench-x86
app-bench-x86: $(benchmark_dependencies)
	make PLATFORM=x86_64 RELEASE=1 TIMING=0 SIM= CONSTRUCTOR=1 SHARED=1 PRELOAD=1 clean all
#	cd benchmarks && ./run_all.sh all

.PHONY: test-x86-pk
test-x86-pk: $(BUILD_DEPS)
	make PLATFORM=x86_64 RELEASE=1 TIMING=0 SIM=pk clean all
	./run/test-x86.sh

.PHONY: test-x86
test-x86: $(BUILD_DEPS)
	make PLATFORM=x86_64 RELEASE=1 TIMING=0 SIM= clean all
	./run/test-x86.sh
