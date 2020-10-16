# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# get Git short hash and tag of latest repository commit
execute_process(COMMAND git describe HEAD
                OUTPUT_VARIABLE DNBD3_VERSION
                OUTPUT_STRIP_TRAILING_WHITESPACE)
if(DNBD3_VERSION STREQUAL "")
    set(DNBD3_VERSION "unknown")
endif(DNBD3_VERSION STREQUAL "")

# write dnbd3 version into a new C source file based on the specified version template
configure_file(${VERSION_INPUT_FILE} ${VERSION_OUTPUT_FILE})
