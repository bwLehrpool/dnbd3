# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2021 Manuel Bentele <development@manuel-bentele.de>
#

find_program(ClangFormat_EXECUTABLE NAMES clang-format)

if(ClangFormat_EXECUTABLE)
    execute_process(COMMAND clang-format --version
                    OUTPUT_VARIABLE ClangFormat_VERBOSE_VERSION
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" ClangFormat_VERSION ${ClangFormat_VERBOSE_VERSION})
endif(ClangFormat_EXECUTABLE)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ClangFormat
                                  FOUND_VAR ClangFormat_FOUND
                                  REQUIRED_VARS ClangFormat_EXECUTABLE
                                  VERSION_VAR ClangFormat_VERSION
                                  FAIL_MESSAGE "clang-format is not available! Please install clang-format to lint and format the source code!")
