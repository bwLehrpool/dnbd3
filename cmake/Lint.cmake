# SPDX-License-Identifier: GPL-2.0
#
# CMake macros to check style of source code files
# Copyright (C) 2021 Manuel Bentele <development@manuel-bentele.de>
#

find_package(ClangFormat)
find_package(CheckPatch)

if(ClangFormat_FOUND OR CheckPatch_FOUND)
    # add target to trigger all linter targets
    add_custom_target(lint)
endif(ClangFormat_FOUND OR CheckPatch_FOUND)

# macro to define lint targets
macro(add_linter LINT_NAME LINT_SOURCE_FILES)
    if(ClangFormat_FOUND)
        add_custom_target(${LINT_NAME}
                          COMMAND ${ClangFormat_EXECUTABLE} --Werror --dry-run ${LINT_SOURCE_FILES} ${ARGN}
                          WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                          DEPENDS ${LINT_SOURCE_FILES} ${ARGN})
        add_dependencies(lint ${LINT_NAME})
    endif(ClangFormat_FOUND)
endmacro(add_linter)

# macro to define lint targets for kernel source code files
macro(add_kernel_linter LINT_NAME LINT_IGNORE_OPTIONS LINT_SOURCE_FILES LINT_HEADER_FILES)
    if(CheckPatch_FOUND)
        set(LINT_IGNORE_ARGS "")
        foreach(IGNORE_OPTION ${LINT_IGNORE_OPTIONS})
            list(APPEND LINT_IGNORE_ARGS "--ignore" "${IGNORE_OPTION}")
        endforeach(IGNORE_OPTION ${LINT_IGNORE_OPTIONS})
        add_custom_target(${LINT_NAME}
                          COMMAND ${CheckPatch_EXECUTABLE} --no-tree --max-line-length=120 ${LINT_IGNORE_ARGS} -f ${LINT_SOURCE_FILES} ${LINT_HEADER_FILES}
                          WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                          DEPENDS ${LINT_SOURCE_FILES} ${LINT_HEADER_FILES})
        add_dependencies(lint ${LINT_NAME})
    endif(CheckPatch_FOUND)
endmacro(add_kernel_linter)

if(ClangFormat_FOUND OR CheckPatch_FOUND)
    # add target to trigger all formatter targets
    add_custom_target(lint-fix)
endif(ClangFormat_FOUND OR CheckPatch_FOUND)

# macro to define formatter targets
macro(add_linter_fix LINT_FIX_NAME LINT_FIX_SOURCE_FILES)
    if(ClangFormat_FOUND)
        add_custom_target(${LINT_FIX_NAME}
                          COMMAND ${ClangFormat_EXECUTABLE} --Werror -i ${LINT_FIX_SOURCE_FILES} ${ARGN}
                          WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                          DEPENDS ${LINT_FIX_SOURCE_FILES} ${ARGN})
        add_dependencies(lint-fix ${LINT_FIX_NAME})
    endif(ClangFormat_FOUND)
endmacro(add_linter_fix)

# macro to define formatter targets for kernel source code files
macro(add_kernel_linter_fix LINT_FIX_NAME LINT_FIX_IGNORE_OPTIONS LINT_FIX_SOURCE_FILES LINT_FIX_HEADER_FILES)
    if(CheckPatch_FOUND)
        set(LINT_FIX_IGNORE_ARGS "")
        foreach(IGNORE_OPTION ${LINT_FIX_IGNORE_OPTIONS})
            list(APPEND LINT_FIX_IGNORE_ARGS "--ignore" "${IGNORE_OPTION}")
        endforeach(IGNORE_OPTION ${LINT_FIX_IGNORE_OPTIONS})
        add_custom_target(${LINT_FIX_NAME}
                          COMMAND ${CheckPatch_EXECUTABLE} --no-tree --max-line-length=120 ${LINT_FIX_IGNORE_ARGS} --fix-inplace -f ${LINT_FIX_SOURCE_FILES} ${LINT_FIX_HEADER_FILES}
                          WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                          DEPENDS ${LINT_FIX_SOURCE_FILES} ${LINT_FIX_HEADER_FILES})
        add_dependencies(lint-fix ${LINT_FIX_NAME})
    endif(CheckPatch_FOUND)
endmacro(add_kernel_linter_fix)
