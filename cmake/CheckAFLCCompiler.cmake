# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# check if corresponding AFL C Compiler form original C compiler is available
# if an AFL C compiler is available, then the path to the AFL C compiler is returned in AFL_C_COMPILER
macro(check_afl_c_compiler AFL_C_COMPILER AFL_C_COMPILER_NAME C_COMPILER_PATH C_COMPILER_ID)
    # determine AFL C compiler suffix from original C compiler ID
    if(${C_COMPILER_ID} MATCHES "GNU")
        set(AFL_C_COMPILER_SUFFIX "gcc")
    elseif(${C_COMPILER_ID} MATCHES "Clang")
        set(AFL_C_COMPILER_SUFFIX "clang")
    else(${C_COMPILER_ID} MATCHES "Clang")
        get_filename_component(AFL_C_COMPILER_SUFFIX ${C_COMPILER_PATH} NAME)
    endif(${C_COMPILER_ID} MATCHES "GNU")

    # define search file name and search for AFL C compiler program
    set(AFL_C_COMPILER_SEARCH_NAME "afl-${AFL_C_COMPILER_SUFFIX}")
    find_program(${AFL_C_COMPILER} NAMES ${AFL_C_COMPILER_SEARCH_NAME})

    # return the AFL C compiler name to the caller
    set(${AFL_C_COMPILER_NAME} ${AFL_C_COMPILER_SEARCH_NAME})
endmacro(check_afl_c_compiler)