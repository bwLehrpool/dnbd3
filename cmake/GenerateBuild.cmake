# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# set current build type of the project
set(DNBD3_BUILD ${BUILD_TYPE})
string(TIMESTAMP DNBD3_BUILD_DATE "%Y-%m-%d" UTC)

# write dnbd3 build type into a new C source file based on the specified build file template
configure_file(${BUILD_INPUT_FILE_TEMPLATE} ${BUILD_OUTPUT_FILE})
