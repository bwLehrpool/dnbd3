# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# get Git short hash and tag of latest repository commit
execute_process(COMMAND git describe HEAD
                OUTPUT_VARIABLE DNBD3_BUILD_VERSION
                OUTPUT_STRIP_TRAILING_WHITESPACE)
if(DNBD3_BUILD_VERSION STREQUAL "")
    set(DNBD3_BUILD_VERSION "unknown")
endif(DNBD3_BUILD_VERSION STREQUAL "")

# get status of Git repository
execute_process(COMMAND git status --porcelain
                OUTPUT_VARIABLE DNBD3_GIT_STATUS
                OUTPUT_STRIP_TRAILING_WHITESPACE)

# check if Git repository is dirty
if(NOT DNBD3_GIT_STATUS STREQUAL "")
    # the Git repository is dirty, thus extend the version information
    set(DNBD3_BUILD_VERSION "${DNBD3_BUILD_VERSION}-modified")

    # print a message in Release build configuration to warn about the dirty repository
    if(VERSION_BUILD_TYPE MATCHES "Release")
        message(WARNING "This dnbd3 Git repository is dirty! Please commit or revert all changes for a ${VERSION_BUILD_TYPE} build!")
    endif(VERSION_BUILD_TYPE MATCHES "Release")
endif(NOT DNBD3_GIT_STATUS STREQUAL "")

# set current build type of the project
set(DNBD3_BUILD_TYPE ${VERSION_BUILD_TYPE})

# write dnbd3 version into a new C source file based on the specified version template
configure_file(${VERSION_INPUT_FILE} ${VERSION_OUTPUT_FILE})
