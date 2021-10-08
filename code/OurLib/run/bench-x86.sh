#!/bin/bash
set -e

function cleanup {
    echo "Resetting CPU frequency..."
    ./run/set-cpu-freq.sh disable
}
trap cleanup EXIT

echo "Setting CPU frequency"
./run/set-cpu-freq.sh enable

function print_info {
  echo -en "\e[36m"
  echo -n "$@"
  echo -e "\e[0m"
}

MECHANISMS=( "none" "ptrace" "ptrace_seccomp" "seccomp_user" "ptrace_delegate" "sysmodule" "indirect" )
FILTERS=( "none" "self-donky" "self-mpk" "localstorage" "just-domain" "old-extended-domain")

for m in "${MECHANISMS[@]}"; do
  for f in "${FILTERS[@]}"; do
    if [[ "$f" == "just-domain" && ! "$m" =~ ^(ptrace_delegate|sysmodule|indirect)$ ]] || \
       [[ "$f" == "old-extended-domain" && ! "$m" =~ ^(ptrace_delegate|sysmodule|indirect)$ ]] || \
       [[ "$m" == "none" && ! "$f" == "none" ]]; then
      print_info "Skipping MECHANISM=$m FILTER=$f"
      continue
    fi
    print_info "Benchmarking MECHANISM=$m FILTER=$f"
    MECHANISM=$m FILTER=$f ./x.elf-shared
  done
done


LOCALSTORAGE="/tmp/localstorage_$(id -u)"
DATE=$(date +%Y_%m_%d-%H:%M:%S)
OUTPUT="benchmarks/output_syscalls_$DATE"
mv results $OUTPUT

./benchmarks/plot_syscall_bench_x86_64.py x86_64 $OUTPUT $OUTPUT paper
