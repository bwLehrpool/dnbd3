# SPDX-License-Identifier: GPL-2.0
#
# CMake macros to check style of source code files
# Copyright (C) 2021 Manuel Bentele <development@manuel-bentele.de>
#

find_package(ClangFormat REQUIRED)

# add target to trigger all linter targets
add_custom_target(lint)

# macro to define lint targets
macro(add_linter LINT_NAME LINT_SOURCE_FILES)
    add_custom_target(${LINT_NAME}
                      COMMAND clang-format --Werror --dry-run ${LINT_SOURCE_FILES} ${ARGN}
                      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                      DEPENDS ${LINT_SOURCE_FILES} ${ARGN})
    add_dependencies(lint ${LINT_NAME})
endmacro(add_linter)

# macro to define lint targets for kernel source code files
macro(add_kernel_linter LINT_NAME KERNEL_BUILD_DIR LINT_SOURCE_FILES LINT_HEADER_FILES)
    add_custom_target(${LINT_NAME}
                      COMMAND ${KERNEL_BUILD_DIR}/scripts/checkpatch.pl --no-tree -f ${LINT_SOURCE_FILES} ${LINT_HEADER_FILES}
                      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                      DEPENDS ${LINT_SOURCE_FILES} ${LINT_HEADER_FILES})
    add_dependencies(lint ${LINT_NAME})
endmacro(add_kernel_linter)

# add target to trigger all formatter targets
add_custom_target(lint-fix)

# macro to define formatter targets
macro(add_linter_fix LINT_FIX_NAME LINT_FIX_SOURCE_FILES)
    add_custom_target(${LINT_FIX_NAME}
                      COMMAND clang-format --Werror -i ${LINT_FIX_SOURCE_FILES} ${ARGN}
                      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                      DEPENDS ${LINT_FIX_SOURCE_FILES} ${ARGN})
    add_dependencies(lint-fix ${LINT_FIX_NAME})
endmacro(add_linter_fix)

# macro to define formatter targets for kernel source code files
macro(add_kernel_linter_fix LINT_FIX_NAME KERNEL_BUILD_DIR LINT_FIX_SOURCE_FILES LINT_FIX_HEADER_FILES)
    add_custom_target(${LINT_FIX_NAME}
                      COMMAND ${KERNEL_BUILD_DIR}/scripts/checkpatch.pl --no-tree --fix-inplace -f ${LINT_FIX_SOURCE_FILES} ${LINT_FIX_HEADER_FILES}
                      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                      DEPENDS ${LINT_FIX_SOURCE_FILES} ${LINT_FIX_HEADER_FILES})
    add_dependencies(lint-fix ${LINT_FIX_NAME})
endmacro(add_kernel_linter_fix)
