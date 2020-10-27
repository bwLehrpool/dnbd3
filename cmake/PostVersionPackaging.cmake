# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

if(EXISTS ${VERSION_HEADER_INPUT_FILE})
    # remove version.h if generated version.h is available from a Git build
    file(REMOVE ${VERSION_HEADER_OUTPUT_FILE})
endif(EXISTS ${VERSION_HEADER_INPUT_FILE})
