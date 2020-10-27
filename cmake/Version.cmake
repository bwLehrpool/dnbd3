# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

macro(gen_project_version VERSION_INPUT_FILE VERSION_INPUT_FILE_TEMPLATE VERSION_OUTPUT_FILE)
    get_filename_component(VERSION_OUTPUT_FILENAME ${VERSION_OUTPUT_FILE} NAME)
    # command that will trigger a rebuild of version.h every time
    add_custom_command(OUTPUT regenerate-version-file
                       COMMAND ${CMAKE_COMMAND} -E sleep 0
                       COMMENT "Trigger generating ${VERSION_OUTPUT_FILENAME}")

    # call the GenerateVersion.cmake file to generate the version.c file
    add_custom_command(OUTPUT ${VERSION_OUTPUT_FILE}
                       COMMAND ${CMAKE_COMMAND} -D VERSION_MODULE_PATH=${PROJECT_MODULES_DIR}
                                                -D VERSION_INPUT_FILE=${VERSION_INPUT_FILE}
                                                -D VERSION_INPUT_FILE_TEMPLATE=${VERSION_INPUT_FILE_TEMPLATE}
                                                -D VERSION_OUTPUT_FILE=${VERSION_OUTPUT_FILE}
                                                -D VERSION_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                                                -P ${PROJECT_MODULES_DIR}/GenerateVersion.cmake
                       COMMENT "Generating ${VERSION_OUTPUT_FILENAME}"
                       DEPENDS regenerate-version-file)
    add_custom_target(dnbd3-generate-version DEPENDS ${VERSION_OUTPUT_FILE})

    # create target to expose project version
    add_library(dnbd3-version INTERFACE)
    target_include_directories(dnbd3-version INTERFACE ${PROJECT_INCLUDE_GEN_DIR})
    add_dependencies(dnbd3-version dnbd3-generate-version)
endmacro(gen_project_version VERSION_INPUT_FILE VERSION_INPUT_FILE_TEMPLATE VERSION_OUTPUT_FILE)

# macro to get Git version information
macro(get_repository_version REPOSITORY_VERSION VERSION_HEADER_FILE VERSION_BUILD_TYPE)
    # check if generated version header from source package is available
    if(EXISTS ${VERSION_HEADER_FILE})
        # get version information from the generated version header of the source package
        file(READ ${VERSION_HEADER_FILE} GIT_VERSION)
        string(REGEX MATCH "\"(([0-9]+:)?[0-9][A-Za-z0-9.+~-]*)\"" GIT_VERSION ${GIT_VERSION})
        set(GIT_VERSION "${CMAKE_MATCH_1}")
    else(EXISTS ${VERSION_HEADER_FILE})
        # get detailed Git version information from Git repository
        execute_process(COMMAND git describe HEAD
                        OUTPUT_VARIABLE GIT_VERSION
                        OUTPUT_STRIP_TRAILING_WHITESPACE)

        # remove the first letter of the version to satisfy packaging rules
        string(REGEX MATCH "([0-9]+:)?[0-9][A-Za-z0-9.+~-]*" GIT_VERSION ${GIT_VERSION})

        # overwrite version from Git if version is unknown
        if(GIT_VERSION STREQUAL "")
            set(GIT_VERSION "unknown")
        endif(GIT_VERSION STREQUAL "")

        # get status of Git repository
        execute_process(COMMAND git status --porcelain
                        OUTPUT_VARIABLE GIT_STATUS
                        OUTPUT_STRIP_TRAILING_WHITESPACE)

        # check if Git repository is dirty
        if(NOT GIT_STATUS STREQUAL "")
            # the Git repository is dirty, thus extend the version information
            set(GIT_VERSION "${GIT_VERSION}-modified")

            # print a message in Release build configuration to warn about the dirty repository
            if(${VERSION_BUILD_TYPE} MATCHES "Release")
                message(WARNING "This dnbd3 Git repository is dirty! Please commit or revert all changes for a ${VERSION_BUILD_TYPE} build!")
            endif(${VERSION_BUILD_TYPE} MATCHES "Release")
        endif(NOT GIT_STATUS STREQUAL "")
    endif(EXISTS ${VERSION_HEADER_FILE})

    # return version to caller
    set(${REPOSITORY_VERSION} ${GIT_VERSION})
endmacro(get_repository_version)
