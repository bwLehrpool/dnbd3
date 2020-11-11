# SPDX-License-Identifier: GPL-2.0
#
# CMAKE toolchain file for cross compilation with powerpc-linux-gnu-gcc
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ppc)

set(CMAKE_C_COMPILER powerpc-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER powerpc-linux-gnu-g++)
set(CMAKE_LINKER powerpc-linux-gnu-ld)
set(CMAKE_ASM_COMPILER powerpc-linux-gnu-as)
set(CMAKE_OBJCOPY powerpc-linux-gnu-objcopy)
set(CMAKE_STRIP powerpc-linux-gnu-strip)
set(CMAKE_CPP powerpc-linux-gnu-cpp)

# path of headers and libraries for powerpc-linux-gnu target
set(CMAKE_FIND_ROOT_PATH "/usr/powerpc-linux-gnu")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
