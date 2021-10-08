#!/bin/bash

### Build a kernel with our PKRU-signal patch ###

# Prerequisites:
# Install necessary packages, see https://wiki.ubuntu.com/Kernel/BuildYourOwnKernel

# Fetch Ubuntu sources (approx. 1.2GB)
git clone -b Ubuntu-5.4.0-55.61 --depth 1 git://kernel.ubuntu.com/ubuntu/ubuntu-focal.git
cd ubuntu-focal

# Apply patch
git am ../00*.patch

# Set config with reduced modules for faster builds
cp ../.config .config
yes '' | make oldconfig

# Build Ubuntu .deb package (approx. 14GB)
CC="ccache gcc" make -j `getconf _NPROCESSORS_ONLN` bindeb-pkg LOCALVERSION=-custom

# Note, the kernel version string might not show 5.4.0-55 but an incorrect higher number.
# You can identify the correct kernel via the appended string '-custom'

exit 0

# Install kernel with:
# sudo dpkg -i linux-headers-XXX.deb
# sudo dpkg -i linux-image-XXX.deb

# Reboot into the new kernel with:
# sudo reboot

# and manually check the kernel version
uname -a

# Now you can run the tests with enabled KERNEL_PATCH
MECHANISM=indirect FILTER=self-mpk make PLATFORM=x86_64 RELEASE=1 SHARED=1 PRELOAD=1 CONSTRUCTOR=1 KERNEL_PATCH=1 clean run
