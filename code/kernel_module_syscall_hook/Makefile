mkfile_path := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
obj-m += sysfilter.o
ccflags-y += -Wno-unused-result
all: test sysfilter.ko

sysfilter.ko: sysfilter.c
	make -C /lib/modules/$(shell uname -r)/build M=$(mkfile_path) modules

test: test.c
	gcc test.c -o test -g -Wl,--section-start=.ssm=$(shell grep START secure_monitor.h | grep -oE "[0-9x]+") -static -pthread

run_test: test
	./test

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(mkfile_path) clean
	rm -f test
#rm -f sysfilter.ko sysfilter.o sysfilter.mod sysfilter.mod.c sysfilter.mod.o modules.order Module.symvers

load: sysfilter.ko
	@if ( ! test -e /dev/sysfilter ); then sudo insmod sysfilter.ko; else echo "Module already loaded"; fi
	@if ( ! lsmod | grep sysfilter ); then echo "Unable to load module!"; exit 1; else echo "Module loaded"; fi

unload:
	@if ( test -e /dev/sysfilter ); then sudo rmmod sysfilter.ko; else echo "No module loaded"; fi
	@if ( lsmod | grep sysfilter ); then echo "Unable to unload module!"; exit 1; else echo "Module unloaded"; fi
