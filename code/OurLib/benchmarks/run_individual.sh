#!/bin/bash
set -e # Halt on error
#set -x

# ------------------------------------------------------------------------------
function print_error {
  echo -en "\e[101m"
  echo -n "$@"
  echo -e "\e[0m"
}
function print_info {
  echo -en "\e[36m"
  echo -n "$@"
  echo -e "\e[0m"
}
# ------------------------------------------------------------------------------
# parse arguments

if [[ "$#" -eq "0" ]]; then
  print_error "Provide program to execute as arguments, with all its necessary flags. E.g.:"
  print_error "$0 ls -lah"
  exit 1
fi
if [ -z "$1" ] ; then
  print_error "Error: 1st argument must be the command to be executed"
  exit 1
fi
if [ -z "$4" ] ; then
  print_error "Error: 4th argument must be the test-case name (without spaces or special characters)"
  exit 1
fi
if [ -z "$OUTDIR" ] ; then
  print_error "OUTDIR was not passed as an environment variable."
  OUTDIR="test"
  print_error "Setting OUTDIR to ${OUTDIR:?}"
  #exit 1
fi
if [ -z "$ITERATIONS" ] ; then
  print_error "ITERATIONS was not passed as an environment variable."
  ITERATIONS=1
  print_error "Setting ITERATIONS to ${ITERATIONS:?}"
  #exit 1
fi
if [ -z "$ITERATIONS_LMBENCH" ] ; then
  print_error "ITERATIONS_LMBENCH was not passed as an environment variable."
  ITERATIONS_LMBENCH=1
  print_error "Setting ITERATIONS_LMBENCH to ${ITERATIONS_LMBENCH:?}"
  #exit 1
fi
if [ -z "$ITERATIONS_NGINX" ] ; then
  print_error "ITERATIONS_NGINX was not passed as an environment variable."
  ITERATIONS_NGINX=1
  print_error "Setting ITERATIONS_NGINX to ${ITERATIONS_NGINX:?}"
  #exit 1
fi

CMD="$1"
CHECK="$2"
CLEANUP="$3"
TC_NAME="$4"
CMD2="$5"
CMD3="$6"

# ------------------------------------------------------------------------------
# setup

MYPATH=..
MYPRELOADWITHOUTPK=${MYPATH:?}/../testroot/root/lib/libc.so.6:${MYPATH:?}/../testroot/root/lib/libpthread.so
MYPRELOAD=${MYPATH:?}/libpku.so:${MYPATH:?}/libpk.so:${MYPRELOADWITHOUTPK:?}
MY_LD_LIBRARY_PATH=${MYPATH:?} 
RESULTFILE_NAME=output_$(echo ${TC_NAME:?} | sed -r "s/\/| /_/g")
RESULTFILE=${OUTDIR:?}/${RESULTFILE_NAME:?}.csv
echo "RESULTFILE = $RESULTFILE"
echo "# $TC_NAME" > ${RESULTFILE}
echo "# $CMD" >> ${RESULTFILE}
echo "mechanism;filter;value;overall" >> ${RESULTFILE}

# ------------------------------------------------------------------------------
function cleanup_nginx {
  #grep -R 'Requests per second' ${RESULTFILE}.* | sed 's/\(:\|csv\.\)/\t/g' | awk 'BEGIN { FS = "\t" } ; { print $4, $6 }' | column -t | sort -k2 -n || true

  killall nginx || true
}
# ------------------------------------------------------------------------------
function post_process_result(){
  #echo "post_process_result"
  #echo "    MECHANISM   = ${MECHANISM:?}"
  #echo "    FILTER      = ${FILTER:?}"
  #echo "    RESULTFILE  = ${RESULTFILE:?}"
  #echo "    STDERR_FILE = ${STDERR_FILE:?}"
  #echo "    TC_NAME     = ${TC_NAME:?}"
  #echo "    CMD         = ${CMD:?}"

  # removing "set -x" output and also colored debug output from our library
  sed -i '/^++\|^\x1b/d' "${STDERR_FILE:?}"

  # Note: storing picoseconds instead of microseconds
  # Note: stderr file also contains lines from previous executions, thus
  #       we use tail -n1 to get the latest
  local value=""
  if [[ "$CMD" =~ lat_syscall|lat_pipe|lat_select|lat_unix|lat_pagefault|lat_udp|lat_tcp|lat_connect|lat_proc|lat_sig ]]; then
    value=$(cat "${STDERR_FILE:?}" | sed 's/.* \([0-9\.]*\) microseconds/\1/' | awk -v OFMT='%d' '{x=$1*1000*1000; print x}' | tail -n1)
  elif [[ "$CMD" =~ lat_ctx ]]; then
    # 2nd column = microseconds
    value=$(cat "${STDERR_FILE:?}" | grep -ih 'size=0k' -A1 | grep '^2 ' | sed 's/^2 \(.*\)/\1/' | awk -v OFMT='%d' '{x=$1*1000*1000; print x}' | tail -n1)
  elif [[ "$CMD" =~ lmdd ]]; then
    # assuming "print=3" value is in KB/s
    # inverting/converting KB/s to ps/KB
    value=$(cat "${STDERR_FILE:?}" | sed 's/\(.*\) KB.*/\1/' | awk -v OFMT='%d' '{x=1000*1000*1000*1000/$1; print x}' | tail -n1)
  elif [[ "$CMD" =~ lat_mmap ]]; then
    #  Output format is "%0.2f %d\\n", megabytes, usecs
    # 2nd column = microseconds
    value=$(cat "${STDERR_FILE:?}" | sed 's/\(.*\) \(.*\)/\2/' | tail -n1)
  elif [[ "$CMD" =~ lat_mem_rd ]]; then
    value=$(cat "${STDERR_FILE:?}" | grep -ih 'stride' -A1 | grep -v 'stride' | awk '{x=$2*1000; print x}' | tail -n1)
  elif [[ "$CMD" =~ lat_fs ]]; then
    # output: size of file, number created, creations per second, and removals per second.
    value=$(cat "${STDERR_FILE:?}" | grep '^0k' | awk '{print $2}' | tail -n1)
  elif [[ "$CMD" =~ bw_tcp|bw_unix|lat_http ]]; then
    # converting MB/sec to ns/MB
    value=$(cat "${STDERR_FILE:?}" | sed 's/.* \([0-9\.]*\) MB\/sec/\1/' | awk -v OFMT='%d' '{x=1000*1000*1000/$1; print x}' | tail -n1)
  else
    print_error "Unhandled case"
  fi

  # write to actual result-file
  if [[ ! -z "$value" ]]; then 
    echo "${MECHANISM};${FILTER};${value};0" >> ${RESULTFILE}
  fi

}
# ------------------------------------------------------------------------------
function bench() {
  export MECHANISM=$1
  export FILTER=$2

  local LOCAL_LD_LIBRARY_PATH=${MY_LD_LIBRARY_PATH:?} # local copy so that we can overwrite it for specific configurations
  local LOCAL_LD_PRELOAD=${MYPRELOAD:?} # local copy so that we can overwrite it for specific configurations

  print_info "benchmarking '$CMD' TC_NAME=$TC_NAME MECHANISM=$MECHANISM FILTER=$FILTER"

  if [[ $CMD =~ "lat_sig" ]]; then
    if [[ "$FILTER" == "none" && "$MECHANISM" == "none" ]]; then
      # disable preloading of our library so that we can use signals
      # otherwise signal handlers would segfault because our stacks are protected
      LOCAL_LD_LIBRARY_PATH=$LD_LIBRARY_PATH
      #LOCAL_LD_PRELOAD=$LD_PRELOAD
      LOCAL_LD_PRELOAD=${MYPRELOADWITHOUTPK:?}
    fi
  fi

  # Do some warmup iterations
  print_info "warmup $TC_NAME"
  LD_LIBRARY_PATH=${LOCAL_LD_LIBRARY_PATH} LD_PRELOAD=${LOCAL_LD_PRELOAD} eval $CLEANUP &> /dev/null || true
  LD_LIBRARY_PATH=${LOCAL_LD_LIBRARY_PATH} LD_PRELOAD=${LOCAL_LD_PRELOAD} eval $CMD
  LD_LIBRARY_PATH=${LOCAL_LD_LIBRARY_PATH} LD_PRELOAD=${LOCAL_LD_PRELOAD} eval $CHECK
  LD_LIBRARY_PATH=${LOCAL_LD_LIBRARY_PATH} LD_PRELOAD=${LOCAL_LD_PRELOAD} eval $CLEANUP
  LD_LIBRARY_PATH=${LOCAL_LD_LIBRARY_PATH} LD_PRELOAD=${LOCAL_LD_PRELOAD} eval $CMD &> /dev/null
  LD_LIBRARY_PATH=${LOCAL_LD_LIBRARY_PATH} LD_PRELOAD=${LOCAL_LD_PRELOAD} eval $CLEANUP &> /dev/null

  STDOUT_FILE=/dev/null
  STDERR_FILE=/dev/null
  if [[ $CMD =~ "lmbench" ]]; then
    STDOUT_FILE=${RESULTFILE:?}.${MECHANISM:?}.${FILTER:?}.stdout
    STDERR_FILE=${RESULTFILE:?}.${MECHANISM:?}.${FILTER:?}.stderr
    echo -n > "${STDOUT_FILE:?}"
    echo -n > "${STDERR_FILE:?}"
  fi

  print_info "benchmark $TC_NAME"
  actual_iterations=${ITERATIONS:?}
  if [[ $CMD =~ "lmbench" ]]; then
    actual_iterations=${ITERATIONS_LMBENCH:?}
  fi

  for i in `seq 1 $actual_iterations`; do
    # for bin/true only, we measure the overall execution time
    if [ "$CMD" = "/usr/bin/true" ] ; then
      echo -n "$MECHANISM;$FILTER;0;" >> ${RESULTFILE}
      OVERALL=${RESULTFILE} MY_LIBRARY_PATH=${LOCAL_LD_LIBRARY_PATH} MY_PRELOAD=${LOCAL_LD_PRELOAD} eval ./overalltiming/overalltiming $CMD &> /dev/null
    elif [[ $CMD =~ "lmbench" ]]; then
      # lmbench writes their own measurements to stderr. it doesnt use stdout
      set +e
      LD_LIBRARY_PATH=${LOCAL_LD_LIBRARY_PATH} LD_PRELOAD=${LOCAL_LD_PRELOAD} eval $CMD 2>> ${STDERR_FILE:?}
      set -e
      post_process_result
    else
      FILE=${RESULTFILE} LD_LIBRARY_PATH=${LOCAL_LD_LIBRARY_PATH} LD_PRELOAD=${LOCAL_LD_PRELOAD} eval $CMD >> ${STDOUT_FILE} 2>> ${STDERR_FILE}
      sed '$s/$/0\n/' -i "${RESULTFILE}" # add 0 overalltiming AND line-break to make it consistent
    fi
    LD_LIBRARY_PATH=${LOCAL_LD_LIBRARY_PATH} LD_PRELOAD=${LOCAL_LD_PRELOAD} eval $CLEANUP &> /dev/null
    echo -n "."
  done
  echo "" # newline for the dots
}
# ------------------------------------------------------------------------------
function bench_server() {
  export MECHANISM=$1
  export FILTER=$2
  local LOCAL_LD_LIBRARY_PATH=${MY_LD_LIBRARY_PATH:?} # local copy so that we can overwrite it for specific configurations
  local LOCAL_LD_PRELOAD=${MYPRELOAD:?} # local copy so that we can overwrite it for specific configurations

  print_info "benchmarking server: '$CMD' TC_NAME=$TC_NAME MECHANISM=$MECHANISM FILTER=$FILTER CMD2='$CMD2' CMD3='$CMD3'"

  if [[ $TC_NAME =~ "nginx_native" ]]; then
    if [[ "$FILTER" == "none" && "$MECHANISM" == "none" ]]; then
      # disable preloading of our library so that we can use signals
      # otherwise signal handlers would segfault because our stacks are protected
      LOCAL_LD_LIBRARY_PATH=$LD_LIBRARY_PATH
      #LOCAL_LD_PRELOAD=$LD_PRELOAD
      LOCAL_LD_PRELOAD=${MYPRELOADWITHOUTPK:?}
    else
      # nginx_native with mechanism != none does not exist
      print_info "skipping: TC_NAME=$TC_NAME MECHANISM=$MECHANISM FILTER=$FILTER"
      return
    fi
  elif [[ $TC_NAME =~ "nginx" ]]; then # custom nginx
    if [[ "$FILTER" != "none" ]]; then
      if [[ "$FILTER" == "localstorage" ]]; then
        export FILTER="nginx" # use our custom filter (+ re-export)
      else
        print_info "skipping: TC_NAME=$TC_NAME MECHANISM=$MECHANISM FILTER=$FILTER"
        return
      fi
    fi
  fi

  #strace:
  if [[ $TC_NAME =~ "nginx_native" ]]; then
    mkdir -p ${OUTDIR:?}/straces
    #start server
    eval $CLEANUP &> /dev/null || true
    strace -o "${OUTDIR:?}/straces/${RESULTFILE_NAME}.strace" -fC $CMD &
    sleep 0.5 # TODO wait until server is ready
    # benchmark
    $CMD2 > /dev/null
    # kill server
    eval $CLEANUP || true
  fi


  # normal benchmark:
  # start server
  eval $CLEANUP &> /dev/null || true
  LD_LIBRARY_PATH=${LOCAL_LD_LIBRARY_PATH} LD_PRELOAD=${LOCAL_LD_PRELOAD} eval $CMD &
  pid="$!"

  sleep 0.5 # TODO wait until server is ready

  STDOUT_FILE=${RESULTFILE:?}.${MECHANISM:?}.${FILTER:?}
  echo -n > "${STDOUT_FILE:?}"

  # start client
  $CMD3 # warmup command

  for i in `seq 1 ${ITERATIONS_NGINX:?}`; do
    $CMD2 >> ${STDOUT_FILE:?}

    # store results in different format:
    if [[ "$TC_NAME" =~ nginx ]]; then
      # check for errors.
      ! grep "Non-2xx" "${STDOUT_FILE:?}"
      # storing picoseconds-per-request
      value=$(grep 'Requests per second' "${STDOUT_FILE:?}" | awk -v OFMT='%d' '{x=1000000000/$4; print x}' | tail -n1)
      echo "${MECHANISM};${FILTER};${value};0" >> ${RESULTFILE}
    fi
  done


  if ps -p ${pid:?} > /dev/null; then
    # server is still running and didnt crash yet
    # resetting pid, such that the below wait command doesnt panic if the server crashes because we killed it.
    pid=""
  fi

  # kill server
  eval $CLEANUP || true

  if ! wait $pid; then
    print_error "server crashed: '$CMD' TC_NAME=$TC_NAME MECHANISM=$MECHANISM FILTER=$FILTER CMD2='$CMD2' CMD3='$CMD3'"
    false
    # since we have `set -e` the script will abort now if the background task had an issue
  fi
}

# ------------------------------------------------------------------------------
# main

FILTERS=( "none" "self-donky" "self-mpk" "localstorage")

MECHANISMS=( "none" "ptrace_delegate" "sysmodule" "indirect" )
#MECHANISMS=( "none"                   "sysmodule" "indirect" )
#NOTE ptrace_delegate might have issues with lmbench

if [[ "$TC_NAME" =~ nginx ]] ; then
  cleanup_nginx
  trap cleanup_nginx EXIT
else
  # strace without our library
  print_info "running strace with '$CMD'"
  mkdir -p ${OUTDIR:?}/straces
  bash -c "$CLEANUP" &> /dev/null || true
  bash -c "strace -fC $CMD" 2> ${OUTDIR:?}/straces/${RESULTFILE_NAME}.strace
  bash -c "$CLEANUP"

  # overall timing without our library
  if [[ "$TC_NAME" == "true" ]] ; then
    print_info "running overalltiming (${ITERATIONS}x) with '$CMD'"
    for i in `seq 1 $ITERATIONS`; do
      echo -n "nul;nul;0;" >> ${RESULTFILE}
      OVERALL=${RESULTFILE} eval ./overalltiming/overalltiming $CMD &> /dev/null
      bash -c "$CLEANUP"
    done
  fi
fi


for m in "${MECHANISMS[@]}"; do
  for f in "${FILTERS[@]}"; do
    # NOTE: extended-domain only works for some mechanisms
    # NOTE: seccomp_user is incompatible with threads
    # NOTE: none mechanisms only makes sense with no filter
    if [[ "$f" == "old-extended-domain" && ! "$m" =~ ^(ptrace_delegate|sysmodule|indirect)$ ]] || \
       [[ "$TC_NAME" =~ lat_ctx|git|nginx|ffmpeg && "$m" == "seccomp_user" ]] || \
       [[   "$m" == "none" && ! "$f" == "none" ]]; then
      print_info "Skipping TC_NAME=$TC_NAME MECHANISM=$m FILTER=$f"
      continue
    fi

    if [[ "$TC_NAME" =~ nginx ]]; then
      bench_server "$m" "$f"
    else
      bench "$m" "$f"
    fi
  done
done

if [ "$CMD" = "/usr/bin/true" ] ; then
  ./plot_init_overhead.py paper $RESULTFILE
else
  if [ ! -z "$PLOT" ] ; then
    set +e # dont Halt on error
    ./plot_app_bench.py paper $RESULTFILE
    set -e # Halt on error
  fi
fi

