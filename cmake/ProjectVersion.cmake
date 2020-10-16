# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

macro(gen_project_version VERSION_INPUT_FILE VERSION_OUTPUT_FILE)
    get_filename_component(VERSION_OUTPUT_FILENAME ${VERSION_OUTPUT_FILE} NAME)
    # command that will trigger a rebuild of version.c every time
    add_custom_command(OUTPUT regenerate-version-file
                       COMMAND ${CMAKE_COMMAND} -E sleep 0
                       COMMENT "Trigger generating ${VERSION_OUTPUT_FILENAME}")

    # call the GenerateVersion.cmake file to generate the version.c file
    add_custom_command(OUTPUT ${VERSION_OUTPUT_FILE}
                       COMMAND ${CMAKE_COMMAND} -D VERSION_INPUT_FILE=${VERSION_INPUT_FILE}
                                                -D VERSION_OUTPUT_FILE=${VERSION_OUTPUT_FILE}
                                                -P ${PROJECT_MODULES_DIR}/GenerateVersion.cmake
                       COMMENT "Generating ${VERSION_OUTPUT_FILENAME}"
                       DEPENDS regenerate-version-file)
    add_custom_target(dnbd3-generate-version DEPENDS ${VERSION_OUTPUT_FILE})

    # create target to expose project version
    add_library(dnbd3-version INTERFACE)
    target_include_directories(dnbd3-version INTERFACE ${PROJECT_INCLUDE_TMP_DIR})
    add_dependencies(dnbd3-version dnbd3-generate-version)

endmacro(gen_project_version VERSION_INPUT_FILE VERSION_OUTPUT_FILE)
