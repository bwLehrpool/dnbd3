# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# set CMake module path to include version macros
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
                      ${VERSION_MODULE_PATH})

# include version macros
include(Version)

# get Git version of Git repository
get_repository_version(DNBD3_VERSION DNBD3_VERSION_SHORT DNBD3_BRANCH ${VERSION_INPUT_FILE} ${VERSION_BUILD_TYPE} ${GIT_EXECUTABLE} ${REPOSITORY_DIR})

# generate version header if header does not exists
if(NOT EXISTS ${VERSION_INPUT_FILE})
    # write dnbd3 version into a new C source file based on the specified version template
    configure_file(${VERSION_INPUT_FILE_TEMPLATE} ${VERSION_OUTPUT_FILE})
endif(NOT EXISTS ${VERSION_INPUT_FILE})
