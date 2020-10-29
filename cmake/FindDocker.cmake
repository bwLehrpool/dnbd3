# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

find_program(Docker_EXECUTABLE NAMES docker)

if(Docker_EXECUTABLE)
    execute_process(COMMAND docker version --format "{{.Server.Version}}"
                    OUTPUT_VARIABLE Docker_VERSION
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif(Docker_EXECUTABLE)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Docker
                                  FOUND_VAR Docker_FOUND
                                  REQUIRED_VARS Docker_EXECUTABLE
                                  VERSION_VAR Docker_VERSION
                                  FAIL_MESSAGE "Docker is not available! Please install docker to build and run containers!")

