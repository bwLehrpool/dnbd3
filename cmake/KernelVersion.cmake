# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# get Linux kernel version from KERNEL_BUILD_DIR string
macro(get_kernel_version LINUX_KERNEL_VERSION KERNEL_BUILD_DIR)
    string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" LINUX_KERNEL_VERSION ${KERNEL_BUILD_DIR})
    if(LINUX_KERNEL_VERSION STREQUAL "")
        set(LINUX_KERNEL_VERSION "unknown")
    endif(LINUX_KERNEL_VERSION STREQUAL "")
endmacro(get_kernel_version LINUX_KERNEL_VERSION KERNEL_BUILD_DIR)
