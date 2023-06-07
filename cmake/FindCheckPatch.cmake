# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2021 Manuel Bentele <development@manuel-bentele.de>
#

# check if custom Linux kernel script directory was specified
if(NOT KERNEL_SCRIPTS_DIR)
    set(KERNEL_SCRIPTS_DIR "${KERNEL_BUILD_DIR}/scripts"
        CACHE PATH "Path to Linux kernel scripts directory")
endif(NOT KERNEL_SCRIPTS_DIR)

# find the checkpatch.pl script in the given KERNEL_SCRIPTS_DIR
find_program(CheckPatch_EXECUTABLE
             NAMES checkpatch.pl
             PATHS ${KERNEL_SCRIPTS_DIR})


# get the checkpatch.pl version
if(CheckPatch_EXECUTABLE)
    execute_process(COMMAND ${CheckPatch_EXECUTABLE} --version
                    OUTPUT_VARIABLE CheckPatch_VERBOSE_VERSION
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REGEX REPLACE ".*Version:.([0-9]+\\.[0-9]+).*" "\\1" CheckPatch_VERSION "${CheckPatch_VERBOSE_VERSION}")
endif(CheckPatch_EXECUTABLE)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CheckPatch
                                  FOUND_VAR CheckPatch_FOUND
                                  REQUIRED_VARS CheckPatch_EXECUTABLE
                                  VERSION_VAR CheckPatch_VERSION
                                  FAIL_MESSAGE "checkpatch.pl is not available! Please install checkpatch.pl to lint and format the source code!")
