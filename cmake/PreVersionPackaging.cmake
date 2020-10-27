# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

if(EXISTS ${VERSION_HEADER_INPUT_FILE})
    # copy generated version.h into the source repository for packaging purposes
    get_filename_component(VERSION_HEADER_OUTPUT_FILE_PATH ${VERSION_HEADER_OUTPUT_FILE} PATH)
    file(COPY ${VERSION_HEADER_INPUT_FILE} 
         DESTINATION ${VERSION_HEADER_OUTPUT_FILE_PATH})
endif(EXISTS ${VERSION_HEADER_INPUT_FILE})
