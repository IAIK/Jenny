#!/bin/bash

set -e # Halt on error
#set -x

if [[ "$#" -eq "0" ]]; then
    echo "Provide argument: nginx|lmbench|applications|all"
    exit 1
fi

export OUTDIR=output_`date +"%Y_%m_%d-%H:%M:%S"`/
export ITERATIONS=2            # for paper, use 10
export ITERATIONS_LMBENCH=2    # for paper, use 10
export ITERATIONS_NGINX=2      # for paper, use 10
export NGINX_REQUESTS=10      # for paper, use 1000
export NGINX_REQ_CONCURRENT=10
export NGINX_SIZES=(0)
export PLOT=1

TMPDIR="/tmp/$(id -u)" # note this is used both natively but also as a subdirectory within the localstorage dir for each domain
LOCALSTORAGE="/tmp/localstorage_$(id -u)" # must be the same as LOCALSTORAGE_DIR in sfu_extended_filters.c # TODO environment variable

function cleanup {
    echo "Resetting CPU frequency"
    ../run/set-cpu-freq.sh disable
    echo "Cleaning up..."
    find template/ -maxdepth 1 -mindepth 1 -exec rm -rf --preserve-root "${TMPDIR:?}/$(basename {})" \;
}
trap cleanup EXIT

rm -rf --preserve-root ${LOCALSTORAGE:?}
rm -rf --preserve-root ${TMPDIR:?}

echo "Setting CPU frequency"
../run/set-cpu-freq.sh enable

# create necessary directories
mkdir -p "${TMPDIR:?}"
mkdir -p "${OUTDIR:?}"

# copy used libraries/binaries to output dir
cp ../*.so                                  ${OUTDIR:?}/
cp ../../testroot/root/lib/libc.so.6     ${OUTDIR:?}/
cp ../../testroot/root/lib/libpthread.so ${OUTDIR:?}/
cp ../../nginx/objs/nginx                ${OUTDIR:?}/nginx_ours
cp ../../nginx_native/objs/nginx         ${OUTDIR:?}/nginx_native

# ------------------------------------------------------------------------------
function run_lmbench {
  LMBENCH=../../lmbench/bin/x86_64-linux-gnu
  STAT=${TMPDIR:?}/lmbench
  TESTFILE=${TMPDIR:?}/XXX
  #SYNC_MAX=1
  #BENCHRUNS=11 # 11 = default
  LOGFILE_NAME="lmbench.txt"

  # add version to versionfile:
  (cd ${LMBENCH:?}/../../scripts; ./version) >> ${VERSIONFILE:?}

  # log file:
  #EXT=0
  #RESULTS_LOGFILE=${OUTDIR:?}/${LOGFILE_NAME:?}.${EXT:?}
  #while [ -f ${RESULTS_LOGFILE:?} ]
  #do      EXT=`expr ${EXT:?} + 1`
  #  RESULTS_LOGFILE=${OUTDIR:?}/${LOGFILE_NAME:?}.${EXT:?}
  #done
  RESULTS_LOGFILE=${OUTDIR:?}/${LOGFILE_NAME:?}
  echo "# Writing to logfile: ${RESULTS_LOGFILE:?}"

  # prepare files
  mkdir -p ${TMPDIR:?}
  touch ${STAT:?}
  touch ${TESTFILE:?}

  if [ ! -d ${LMBENCH:?}/../../src/webpage-lm ] ; then
    (cd ${LMBENCH:?}/../../src && tar xf webpage-lm.tar)
    sync
  fi

  #NOTE: lmdd creates ${TESTFILE:?} for the other benchmarks

  # ----------------------------------------------------------------------------
  killall lmhttp      &> /dev/null || true
  killall lat_udp     &> /dev/null || true
  killall lat_connect &> /dev/null || true
  killall bw_tcp      &> /dev/null || true
  killall lat_rpc     &> /dev/null || true

  # ----------------------------------------------------------------------------

  #XXX ./run_individual.sh "${LMBENCH:?}/lat_ctx -s 0 2" "" "" "lat_ctx"
  ./run_individual.sh "${LMBENCH:?}/lat_syscall -P 1 null" "" "" "lat_syscall_null"
  ./run_individual.sh "${LMBENCH:?}/lat_syscall -P 1 read" "" "" "lat_syscall_read"
  ./run_individual.sh "${LMBENCH:?}/lat_syscall -P 1 write" "" "" "lat_syscall_write"
  ./run_individual.sh "${LMBENCH:?}/lat_syscall -P 1 stat ${STAT:?}" "" "" "lat_syscall_stat"
  ./run_individual.sh "${LMBENCH:?}/lat_syscall -P 1 fstat ${STAT:?}" "" "" "lat_syscall_fstat"
  ./run_individual.sh "${LMBENCH:?}/lat_syscall -P 1 open ${STAT:?}" "" "" "lat_syscall_open"
  ./run_individual.sh "${LMBENCH:?}/lat_select -n 10 -P 1 file" "" "" "lat_select_10_file"
  #XXX ./run_individual.sh "${LMBENCH:?}/lat_pipe -P 1 -N 4" "" "" "lat_pipe" # very slow
  #XXX ./run_individual.sh "${LMBENCH:?}/lat_unix -P 1" "" "" "lat_unix"
  ./run_individual.sh "${LMBENCH:?}/lmdd of=${TESTFILE:?} move=100m fsync=1 print=3" "" "" "lmdd_100m"
  ./run_individual.sh "${LMBENCH:?}/lat_pagefault -P 1 ${TESTFILE:?}" "" "" "lat_pagefault"
  ./run_individual.sh "${LMBENCH:?}/lat_mmap -P 1 512k ${TESTFILE:?}" "" "" "lat_mmap_512k"
  ./run_individual.sh "${LMBENCH:?}/lat_fs -P 1 ${TMPDIR:?}" "" "" "lat_fs"
  ./run_individual.sh "${LMBENCH:?}/lat_sig -P 1 install" "" "" "lat_sig_install"
  ./run_individual.sh "${LMBENCH:?}/lat_sig -P 1 catch" "" "" "lat_sig_catch"
  ./run_individual.sh "${LMBENCH:?}/lat_sig -P 1 prot ${TESTFILE:?}" "" "" "lat_sig_prot_lat_sig"
  # ./run_individual.sh "${LMBENCH:?}/lat_proc -P 1 fork"  "" "" "lat_proc_fork"
  #XXX ./run_individual.sh "${LMBENCH:?}/bw_unix -P 1 -m 4k -M 4m -W 0 -N 1" "" "" "bw_unix"
  ./run_individual.sh "${LMBENCH:?}/lat_select -n 10  -P 1 tcp" "" "" "lat_select_10_tcp"
  # ---------------------
  ${LMBENCH:?}/lat_udp -s # start server
  ./run_individual.sh "${LMBENCH:?}/lat_udp -P 1 localhost" "" "" "lat_udp_localhost"
  ${LMBENCH:?}/lat_udp -S localhost # stop server
  # ---------------------
  ${LMBENCH:?}/lat_tcp -s # start server
  ./run_individual.sh "${LMBENCH:?}/lat_tcp -P 1 localhost" "" "" "lat_tcp_localhost"
  ${LMBENCH:?}/lat_tcp -S localhost # stop server
  # ---------------------
  ${LMBENCH:?}/lat_connect -s # start server
  ./run_individual.sh "${LMBENCH:?}/lat_connect localhost" "" "" "lat_connect_localhost"
  ${LMBENCH:?}/lat_connect -S localhost # stop server
  # ---------------------
  ${LMBENCH:?}/bw_tcp -s # start server
  ./run_individual.sh "${LMBENCH:?}/bw_tcp -P 1 -m    1 localhost" "" "" "bw_tcp_1"
  ${LMBENCH:?}/bw_tcp -S localhost # stop server
  # ---------------------
  DOCROOT=${LMBENCH:?}/../../src/webpage-lm ${LMBENCH:?}/lmhttp 8008 & # start server
  ./run_individual.sh "${LMBENCH:?}/lat_http localhost 8008 < ../../lmbench/src/webpage-lm/URLS" "" "" "lat_http_localhost"
  ${LMBENCH:?}/lat_http -S localhost 8008 # stop server
  # ----------------------------------------------------------------------------
  # plot
  ./plot_lmbench.py paper ${OUTDIR:?}
  # ----------------------------------------------------------------------------

}

# ------------------------------------------------------------------------------
function run_nginx {
  local nginx_dirs=("nginx_native" "nginx")
  for nginx_dir in "${nginx_dirs[@]}"; do
    for s in "${NGINX_SIZES[@]}"; do
      # no module:
      url="http://localhost:3000/${s:?}KiB"
      ./run_individual.sh "../../${nginx_dir:?}/objs/nginx" "" "killall nginx" "${nginx_dir:?}_${s:?}KiB" "ab -n ${NGINX_REQUESTS:?} -c ${NGINX_REQ_CONCURRENT:?} ${url:?}" "curl --output /dev/null ${url:?}"
      # gz
      url="http://localhost:3000/${s:?}KiB"
        ./run_individual.sh "../../${nginx_dir:?}/objs/nginx" "" "killall nginx" "${nginx_dir:?}_gzip_${s:?}KiB" "ab -H Accept-Encoding:deflate,gzip -n ${NGINX_REQUESTS:?} -c ${NGINX_REQ_CONCURRENT:?} ${url:?}" "curl --output /dev/null ${url:?}"
      # auth+gz
      url="http://localhost:3000/api/${s:?}KiB"
      ./run_individual.sh "../../${nginx_dir:?}/objs/nginx" "" "killall nginx" "${nginx_dir:?}_auth_gzip_${s:?}KiB" "ab -H Accept-Encoding:deflate,gzip -A user1:pass1 -n ${NGINX_REQUESTS:?} -c ${NGINX_REQ_CONCURRENT:?} ${url:?}" "curl --output /dev/null ${url:?}"
    done
  done

  ./plot_nginx_singlefigure.py paper "${OUTDIR:?}"
}

# ------------------------------------------------------------------------------
function run_others {
  # usage: ./run_individual CMD CHECK CLEANUP TESTNAME (CMD2=CLIENT_COMMAND CMD3=WARMUP)
  ./run_individual.sh "/usr/bin/true" "" "" "true"
  ./run_individual.sh "/usr/bin/ls -lah ${TMPDIR:?}/git" "" "" "ls"
  ./run_individual.sh "/usr/bin/grep sshd -R ${TMPDIR:?}/git/Documentation" "" "" "grep"
  ./run_individual.sh "/usr/bin/zip -r ${TMPDIR:?}/gitweb.zip ${TMPDIR:?}/git/gitweb" "" "rm ${TMPDIR:?}/gitweb.zip" "zip"
  ./run_individual.sh "/usr/bin/git -C ${TMPDIR:?}/git status" "" "" "git"
  ./run_individual.sh "/usr/bin/dd if=/dev/zero of=${TMPDIR:?}/test.bin bs=1024 count=1024" "" "rm ${TMPDIR:?}/test.bin" "dd"
  ./run_individual.sh "/usr/bin/openssl dgst -sha256 -sign ${TMPDIR:?}/key.pem -out ${TMPDIR:?}/signature.bin ${TMPDIR:?}/file.bin" "openssl dgst -sha256 -prverify ${TMPDIR:?}/key.pem -signature ${TMPDIR:?}/signature.bin ${TMPDIR:?}/file.bin" "rm ${TMPDIR:?}/signature.bin" "openssl"
  ./run_individual.sh "/usr/bin/sqlite3 ${TMPDIR:?}/db.sqlite '.read ${TMPDIR:?}/test.sql'" "sqlite3 ${TMPDIR:?}/db.sqlite 'SELECT COUNT (*) from t;'" "rm ${TMPDIR:?}/db.sqlite" "sqlite3"
  ./run_individual.sh "/usr/bin/ffmpeg -threads 1 -i ${TMPDIR:?}/BigBuckBunny.mp4 -threads 3 -t 00:00:02 -c:v libx264 -preset ultrafast -loglevel error ${TMPDIR:?}/BigBuckBunny2.mp4" "" "rm ${TMPDIR:?}/BigBuckBunny2.mp4" "ffmpeg"

  ./plot_appbench_singlefigure.py paper "${OUTDIR:?}"
}


# ------------------------------------------------------------------------------
# create and copy template files

# template files for lmbench:
touch template/lmbench
touch template/XXX
dd if=/dev/zero of=template/XXX bs=1MB count=100
#fallocate -l 100MB template/XXX
mkdir -p template/tmp
cp ../../lmbench/bin/x86_64-linux-gnu/hello template/tmp
cp ../../lmbench/bin/x86_64-linux-gnu/hello /tmp/

# template files for git:
if [[ ! -e template/git ]]; then
  git clone --branch v2.30.0-rc0 --depth 10000 https://github.com/git/git.git template/git
fi

# template files for ffmpeg:
if [[ ! -f template/BigBuckBunny.mp4 ]]; then
  wget -O template/BigBuckBunny.mp4 http://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4
  if [[ ! -f template/BigBuckBunny.mp4 ]]; then
    echo "Unable to download BigBuckBunny.mp4"
    exit 1
  fi
fi

# template files for nginx:
mkdir -p template/usr/local/nginx/conf
mkdir -p template/usr/local/nginx/logs
mkdir -p /tmp/www

mkdir -p template/tmp/www
touch template/usr/local/nginx/logs/error.log
cp  ../../nginx_aux/conf/* template/usr/local/nginx/conf/

sudo chmod -R ugo+rw /usr/local/nginx
sudo chmod -R ugo+rw /tmp/www


echo "test" > /tmp/www/index.html
for s in ${NGINX_SIZES}; do
  OUT=/tmp/www/${s}KiB
  dd if=/dev/zero of=${OUT} bs=1k count=${s}
done
cp -Rf /tmp/www template/tmp/

# misc
# maybe: ln -s "/dev/zero" "template/dev/"

# ------------------------------------------------------------------------------
# copy template to tmpfs directory
# (and symlink everything again into the local storage directories)

cp -fR template/* "${TMPDIR:?}"
for domain in 0 1 2 3 4; do
  mkdir -p "${LOCALSTORAGE:?}/${domain:?}/$(dirname ${TMPDIR:?})"
  #cp -fR template/* "${LOCALSTORAGE:?}/${domain:?}/${TMPDIR:?}"
  ln -s "${TMPDIR:?}"         "${LOCALSTORAGE:?}/${domain:?}/$(dirname ${TMPDIR:?})/"
  ln -s "${TMPDIR:?}/usr"     "${LOCALSTORAGE:?}/${domain:?}/"
  ln -s "${TMPDIR:?}/tmp/www" "${LOCALSTORAGE:?}/${domain:?}/tmp/"
  ln -s "${TMPDIR:?}/etc"     "${LOCALSTORAGE:?}/${domain:?}/"
done

tree -I git -h "${TMPDIR:?}"
tree -I git -h "${LOCALSTORAGE:?}"

# ------------------------------------------------------------------------------
# remember application versions:
VERSIONFILE=${OUTDIR:?}/versions.txt
ls --version                 >> ${VERSIONFILE:?}
grep --version               >> ${VERSIONFILE:?}
zip --version                >> ${VERSIONFILE:?}
git --version                >> ${VERSIONFILE:?}
dd --version                 >> ${VERSIONFILE:?}
sqlite3 --version            >> ${VERSIONFILE:?}
openssl version              >> ${VERSIONFILE:?}
MECHANISM=none FILTER=none LD_LIBRARY_PATH=.. LD_PRELOAD=../libpku.so:../libpk.so:../../testroot/root/lib/libc.so.6:../../testroot/root/lib/libpthread.so ../../nginx/objs/nginx -V >> ${VERSIONFILE:?}
# note: lmbench adds itself in run_lmbench

# ------------------------------------------------------------------------------
# run app benchmarks:


if [[ "$1" == "nginx" ]]; then
  run_nginx
elif [[ "$1" == "lmbench" ]]; then
  run_lmbench
elif [[ "$1" == "applications" ]]; then
  run_others
elif [[ "$1" == "all" ]]; then
  run_nginx
  run_lmbench
  run_others
else
  echo "Invalid argument"
  exit 1
fi
