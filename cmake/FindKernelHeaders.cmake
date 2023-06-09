# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# check if custom Linux kernel build directory was specified
if(NOT KERNEL_BUILD_DIR)
    set(KERNEL_BUILD_DIR "/lib/modules/${CMAKE_SYSTEM_VERSION}/build"
        CACHE PATH "Path to Linux kernel modules to compile against")
endif(NOT KERNEL_BUILD_DIR)

# check if custom Linux kernel output directory was specified
if(NOT KERNEL_INSTALL_DIR)
    set(KERNEL_INSTALL_DIR "/lib/modules/${CMAKE_SYSTEM_VERSION}/extra"
        CACHE PATH "Path to install Linux kernel modules")
endif(NOT KERNEL_INSTALL_DIR)

if(NOT EXISTS "${KERNEL_BUILD_DIR}/Module.symvers")
    message(WARNING "\n\nModule.symvers not found in ${KERNEL_BUILD_DIR}\n"
    "Your kernel sources don't seem to belong to a built kernel,"
    " expect missing symbols when building kernel module.\n\n")
endif()

# find the Linux kernel headers from given KERNEL_BUILD_DIR
find_path(KernelHeaders_INCLUDE_DIR
          NAMES linux/kernel.h
                linux/module.h
                generated/utsrelease.h
          PATHS ${KERNEL_BUILD_DIR}/include
          NO_DEFAULT_PATH)

# get Linux kernel headers version
file(READ "${KERNEL_BUILD_DIR}/include/generated/utsrelease.h" tmpvar)
string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" KernelHeaders_VERSION ${tmpvar})
if("${KernelHeaders_VERSION}" EQUAL "")
    file(READ "${KERNEL_BUILD_DIR}/include/config/kernel.release" tmpvar)
    string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" KernelHeaders_VERSION ${tmpvar})
endif()
if("${KernelHeaders_VERSION}" EQUAL "")
    string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" KernelHeaders_VERSION ${KernelHeaders_INCLUDE_DIR})
endif()
if("${KernelHeaders_VERSION}" EQUAL "")
    message(FATAL_ERROR "Cannot determine kernel version")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(KernelHeaders
                                  FOUND_VAR KernelHeaders_FOUND
                                  REQUIRED_VARS KernelHeaders_INCLUDE_DIR
                                  VERSION_VAR KernelHeaders_VERSION
                                  FAIL_MESSAGE "Linux kernel headers are not available! Please install them to build kernel modules!")

mark_as_advanced(KernelHeaders_INCLUDE_DIR KernelHeaders_MODULE_INSTALL_DIR)

# print found information
if(${CMAKE_VERSION} VERSION_GREATER "3.15.0")
    message(VERBOSE "KERNEL_BUILD_DIR: ${KERNEL_BUILD_DIR}")
    message(VERBOSE "KERNEL_INSTALL_DIR: ${KERNEL_INSTALL_DIR}")
    message(VERBOSE "KernelHeaders_FOUND: ${KernelHeaders_FOUND}")
    message(VERBOSE "KernelHeaders_VERSION: ${KernelHeaders_VERSION}")
endif(${CMAKE_VERSION} VERSION_GREATER "3.15.0")
