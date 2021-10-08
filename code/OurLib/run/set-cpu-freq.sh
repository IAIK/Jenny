#!/usr/bin/bash
set -e

FREQ="1.8GHz"

if [[ "$#" -eq "0" ]]; then
    echo "Provide argument: enable|disable"
    exit 1
fi

if cpupower 2>&1 | grep -q 'WARNING: cpupower not found'; then exit 0; fi
if ! sudo cpupower frequency-set --governor userspace 2>&1 > /dev/null; then echo "cpupower not working properly. Skipping."; exit 0; fi



if [[ "$1" == "enable" ]]; then
    cpupower frequency-info | grep userspace
    if [[ "$?" -ne "0" ]]; then
        echo "Unable to change CPU frequency! Possible reasons:"
        echo "A) Wrong driver loaded. Required driver: 'acpi-cpufreq'. Current driver: $(cpufreq-info -d)"
        echo "B) CPU govenor '${GOV}' not available. Available govenors: $(cpufreq-info -g)"
        echo "   See https://www.kernel.org/doc/Documentation/cpu-freq/governors.txt"
        echo ""
        echo "To solve A:"
        echo "1. Open /etc/default/grub"
        echo "2. Add 'intel_pstate=disable' to GRUB_CMDLINE_LINUX_DEFAULT"
        echo "3. Run 'sudo update-grub'"
        echo "4. Reboot"
        exit 1
    fi
    sudo cpupower frequency-set --governor userspace
    sudo cpupower --cpu all frequency-set --freq ${FREQ}
elif [[ "$1" == "disable" ]]; then
    sudo cpupower frequency-set --governor schedutil
else
  echo "Provide argument: enable|disable"
  exit 1
fi
