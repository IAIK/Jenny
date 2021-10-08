ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
#ROOT_DIR:=$(PWD) # this does not work if the makefile is invoked from a different path

NR_CORES=$(nproc)
NAME="Anonymous"
EMAIL="anonymous@example.org"
GLIBC_URL="git://sourceware.org/git/glibc.git"
GLIBC_TAG="release/2.31/master"

all: build install

glibc/Makefile:
	git clone $(GLIBC_URL)
	cd glibc; \
	git config user.name $(NAME); \
	git config user.email $(EMAIL); \
	git checkout $(GLIBC_TAG); \
	git am ../*.patch

build: build/libc.so

build/libc.so: glibc/Makefile
	mkdir -p build
	touch build
	cd build; \
	../glibc/configure --prefix=$(shell pwd)/root; \
	make -j$(NR_CORES)

install: build root/.done

root/.done:
	mkdir -p root
	make -C build install
	# fixing errors with linking -lm
	mkdir -p root/$(ROOT_DIR)/root/lib
	cp -u root/lib/libm-2.31.a root/$(ROOT_DIR)/root/lib/libm-2.31.a
	cp -u root/lib/libmvec.a root/$(ROOT_DIR)/root/lib/libmvec.a
	touch root/.done

.PHONY: build install clean
clean:
	rm -rf build root root/.done
