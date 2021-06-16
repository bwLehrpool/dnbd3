# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2021 Manuel Bentele <development@manuel-bentele.de>
#

find_file(Stdatomic_INCLUDE_FILE
          NAMES stdatomic.h
          HINTS ${CMAKE_C_IMPLICIT_INCLUDE_DIRECTORIES})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Stdatomic
                                  FOUND_VAR Stdatomic_FOUND
                                  REQUIRED_VARS Stdatomic_INCLUDE_FILE
                                  FAIL_MESSAGE "Compiler does not support atomic operations!")
