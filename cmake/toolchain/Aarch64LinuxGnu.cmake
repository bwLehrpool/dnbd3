# SPDX-License-Identifier: GPL-2.0
#
# CMAKE toolchain file for cross compilation with aarch64-linux-gnu-gcc
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)
set(CMAKE_LINKER aarch64-linux-gnu-ld)
set(CMAKE_ASM_COMPILER aarch64-linux-gnu-as)
set(CMAKE_OBJCOPY aarch64-linux-gnu-objcopy)
set(CMAKE_STRIP aarch64-linux-gnu-strip)
set(CMAKE_CPP aarch64-linux-gnu-cpp)

# path of headers and libraries for aarch64-linux-gnu target
set(CMAKE_FIND_ROOT_PATH "/usr/aarch64-linux-gnu")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
