reldir=lib/strace/strace

OS?=linux

########################################################################
ifeq ($(PLATFORM),x86_64)
STRACE_ARCH=x86_64
endif

ifeq ($(PLATFORM),riscv)
STRACE_ARCH=riscv64
endif

ifndef STRACE_ARCH
$(error Unknown platform $(PLATFORM))
endif
########################################################################


CCFLAGS += -I$(reldir)/$(OS)/$(STRACE_ARCH) \
           -I$(reldir)/$(OS) \
           -I$(reldir)
