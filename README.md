# Jenny

## Directory Structure

* `code/OurLib` contains the source code of Jenny
* `code/kernel_patch_signal_handler` contains the kernel patch for the PKU-safe signals
* `code/kernel_module_syscall_hook` contains our kernel module for syscall interception
* `code/lmbench` contains the unmodified lmbench benchmark-suite
* `code/nginx` contains the modified nginx
* `code/nginx_native` contains the unmodified nginx
* `code/nginx_aux` contains configuration files and patches for the nginx benchmark
* `code/testroot` is used for compiling our modified libc


## Setup Instructions

We have tested our code with Ubuntu 20.04 with Linux 5.4.0 on an Intel Xeon 4208 CPU.
The following instructions assume that a similar system is used.
Notably, the CPU has to support MPK, which means it requires a compatible Intel Xeon Scalable CPU (or at least an AMD 3rd generation Ryzen CPU).
Furthermore, in total, about 10GB of disk space is needed.
The following commands assume that our repository is cloned into `~/jenny`, however, this path can be swapped out to any other directory.

```
echo ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula select true | sudo debconf-set-selections
sudo apt update && sudo apt install -y ffmpeg make build-essential bison clang libpthread-stubs0-dev gcc-10 g++-10 linux-tools-common python3-pip zip sqlite3 libpcre3-dev libssl-dev apache2-utils tree ttf-mscorefonts-installer texlive-base texlive-latex-base texlive-latex-extra texlive-fonts-recommended dvipng cm-super

rm -rf ~/.cache/matplotlib
sudo fc-cache -f

sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 100 --slave /usr/bin/g++ g++ /usr/bin/g++-10 --slave /usr/bin/gcov gcov /usr/bin/gcov-10

pip install matplotlib tikzplotlib scipy pandas termcolor numpy

git clone https://github.com/IAIK/Jenny.git ~/jenny
git submodule update --init --recursive
```

### Optional setup

On our evaluation system we have changed the boot flags of the kernel to allow for a fixed cpu frequency.
In `/etc/default/grub`, we changed the `GRUB_CMDLINE_LINUX_DEFAULT` to also include `intel_pstate=disable` like so: `GRUB_CMDLINE_LINUX_DEFAULT="quiet splash intel_pstate=disable"`.
On the next boot, the changed setting are in effect and can be observed via `cat /proc/cmdline`.

Further, since our benchmarks also operate on files, we mounted the `/tmp` directory as a in-memory "tmpfs" filesystem. This also minimizes jitter from storage devices. For this, we added the following file to `/etc/fstab`.

```
tmpfs                   /tmp            tmpfs           rw,nosuid,nodev,size=2G         0       0
```

## Run

Jenny can be compiled and run with the below commands.
They will then place the benchmark results (including the figures used in the paper) within `~/jenny/code/OurLib/benchmarks`.
Each run will create a new subdirectory with a timestamp and generate plots (pdf files) used in the paper.

Note, however, that the resulting numbers will be different compared to the paper due to different CPU model, CPU frequency, kernel version, etc. Differences are also expected when run in a virtualized environment ((such as Amazon EC2).

We have reduced the number of iterations compared to the paper, such that the results can be generated much quicker.
If desired, the variables `ITERATIONS`, `ITERATIONS_LMBENCH`, `ITERATIONS_NGINX`, and `NGINX_REQUESTS` in `~/jenny/code/OurLib/benchmarks/run_all.sh` can be adapted to match the paper. The values from the paper are commented out in the same file.

### Microbenchmarks (Figure 4, 5)

```
cd ~/jenny/code/OurLib && make bench-x86
```

The above command creates a new directory called `output_syscalls_{datetime}` with the current date and time in `~/jenny/code/OurLib/benchmarks/` where the results reside. 
There, `tc_getpid.pdf` and `tc_open.pdf` should be created, which were used in the paper as Figure 4 and 5.



### Application benchmarks (Figure 6)

The following command compiles our library for the application benchmarks:

```
cd ~/jenny/code/OurLib && make app-bench-x86
```

Afterwards, the individual benchmarks can be run.
Each of the following commands creates a directory called `output_{datetime}` in `~/jenny/code/OurLib/benchmarks/` for the results.

### applications (Figure 6, 10)

```
cd ~/jenny/code/OurLib/benchmarks && ./run_all.sh applications
```

This creates `appbench_single.pdf`, which was used as Figure 6 in the paper.
Furthermore, `output_true_initialization_overhead.pdf` will be created, which is Figure 10 in the paper.

### nginx (Figure 9)

```
cd ~/jenny/code/OurLib/benchmarks && ./run_all.sh nginx
```

This creates `appbench_nginx_single.pdf`, which was used as Figure 9 in the paper.

### lmbench (Figure 7)

```
cd ~/jenny/code/OurLib/benchmarks && ./run_all.sh lmbench
```

Note, that this command can take an hour or longer.
Once finished, it will create `lmbench_numbers.pdf`, which was used as Figure 7 in the paper.

## Troubleshooting

Due to possible race condition bugs in our ptrace implementation, it might happen that some benchmarks sometimes fail or hang. 
In this case, the affected benchmarks can be disabled in `~/jenny/code/OurLib/benchmarks/run_all.sh`.
Alternatively, the array `MECHANISMS` can be updated to remove `ptrace_delegate`.
Afterwards, the above commands be be used to re-run the benchmarks.
