# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

macro(gen_build_type BUILD_INPUT_FILE_TEMPLATE BUILD_OUTPUT_FILE)
    get_filename_component(BUILD_OUTPUT_FILENAME ${BUILD_OUTPUT_FILE} NAME)
    # command that will trigger a rebuild of build.h every time
    add_custom_command(OUTPUT regenerate-build-file
                       COMMAND ${CMAKE_COMMAND} -E sleep 0
                       COMMENT "Trigger generating ${BUILD_OUTPUT_FILENAME}")

    # call the GenerateBuild.cmake file to generate the build.h file
    add_custom_command(OUTPUT ${BUILD_OUTPUT_FILE}
                       COMMAND ${CMAKE_COMMAND} -D BUILD_INPUT_FILE_TEMPLATE=${BUILD_INPUT_FILE_TEMPLATE}
                                                -D BUILD_OUTPUT_FILE=${BUILD_OUTPUT_FILE}
                                                -D BUILD_TYPE=${CMAKE_BUILD_TYPE}
                                                -P ${PROJECT_MODULES_DIR}/GenerateBuild.cmake
                       COMMENT "Generating ${BUILD_OUTPUT_FILENAME}"
                       DEPENDS regenerate-build-file)
    add_custom_target(dnbd3-generate-build DEPENDS ${BUILD_OUTPUT_FILE})

    # create target to expose project build type
    add_library(dnbd3-build INTERFACE)
    target_include_directories(dnbd3-build INTERFACE ${PROJECT_INCLUDE_GEN_DIR})
    add_dependencies(dnbd3-build dnbd3-generate-build)
endmacro(gen_build_type BUILD_INPUT_FILE_TEMPLATE BUILD_OUTPUT_FILE)
