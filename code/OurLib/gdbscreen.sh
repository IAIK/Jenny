#!/bin/bash

TTY=`tty`
TTY=${TTY#/dev/pts/}
SNAME=gdbsession$TTY
TTYFILE=.tty$TTY

screen -S ${SNAME} -X quit

# Screen session with horizontal separator
IFS='' read -r -d '' SCREEN <<"EOF"
layout new
split -v
screen 0
defscrollback 100000
focus next
screen 1
focus next
detach
EOF

# GDB arguments
IFS='' read -r -d '' GDB <<"EOF"
directory ../../testroot/glibc/elf
handle SIGSEGV pass stop
layout split
EOF

GDB="set exec-wrapper env 'LD_PRELOAD=$DO_LD_PRELOAD'
${GDB}"
rm -f ${TTYFILE}

echo "Creating new screen session"
echo "${SCREEN}" > .gdbscreen
screen -S ${SNAME} -c .gdbscreen

echo "Determining tty"
screen -S ${SNAME} -p0 -X stuff "echo Hallo\n"
screen -S ${SNAME} -p1 -X stuff "tty > ${TTYFILE}\n"
echo "Waiting for screen"
i=0
while [[ ! -f ${TTYFILE} ]]; do
  echo -n "."
  sleep 0.1
  i=$((i+1))
  if [[ "$i" -gt "10" ]]; then
    echo "Timeout!"
    screen -S ${SNAME} -X quit
    exit 1
  fi
done

echo "Running $*"
echo "tty `cat ${TTYFILE}`" > .gdb
echo "${GDB}" >> .gdb

screen -S ${SNAME} -p0 -X stuff "export LD_LIBRARY_PATH=$LD_LIBRARY_PATH\n"
screen -S ${SNAME} -p0 -X stuff "$* && screen -S ${SNAME} -X quit\n"

echo "Attaching"
screen -rS ${SNAME}
