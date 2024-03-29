cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-kernel
        LANGUAGES C)

# include macros to define Linux kernel build targets
include(Kernel)

# set C flags for a Linux kernel module
set(KERNEL_C_FLAGS "-DDNBD3_KERNEL_MODULE -I ${PROJECT_INCLUDE_GEN_DIR}"
    CACHE STRING "C flags to be used for building the dnbd3 kernel module")
# set C flags for the debug mode of a Linux kernel module
set(KERNEL_C_FLAGS_DEBUG "-g -DDEBUG"
    CACHE STRING "Additional C flags to be used for building the dnbd3 kernel module in debug mode")

# append include directories to the C flags
get_property(KERNEL_INCLUDE_DIRS DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)
foreach(KERNEL_INCLUDE_DIR ${KERNEL_INCLUDE_DIRS})
    set(KERNEL_C_FLAGS "${KERNEL_C_FLAGS} -I ${KERNEL_INCLUDE_DIR}")
endforeach(KERNEL_INCLUDE_DIR ${KERNEL_INCLUDE_DIRS})

# append debug C flags if debug mode is enabled
if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(KERNEL_C_FLAGS "${KERNEL_C_FLAGS} ${KERNEL_C_FLAGS_DEBUG}")
endif(CMAKE_BUILD_TYPE MATCHES Debug)

# dnbd3 Linux kernel module
set(KERNEL_MODULE_DNBD3_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/blk.c
                                     ${CMAKE_CURRENT_SOURCE_DIR}/dnbd3_main.c
                                     ${CMAKE_CURRENT_SOURCE_DIR}/net.c
                                     ${CMAKE_CURRENT_SOURCE_DIR}/serialize.c
                                     ${CMAKE_CURRENT_SOURCE_DIR}/sysfs.c)
set(KERNEL_MODULE_DNBD3_HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/blk.h
                                     ${CMAKE_CURRENT_SOURCE_DIR}/dnbd3_main.h
                                     ${CMAKE_CURRENT_SOURCE_DIR}/net.h
                                     ${CMAKE_CURRENT_SOURCE_DIR}/sysfs.h)

add_kernel_module(dnbd3 "${KERNEL_BUILD_DIR}"
                        "${KERNEL_INSTALL_DIR}"
                        "CONFIG_BLK_DEV_DNBD3=m"
                        "${KERNEL_MODULE_DNBD3_SOURCE_FILES}"
                        "${KERNEL_MODULE_DNBD3_HEADER_FILES}"
                        ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild)

# add dependency to generate project version header before dnbd3.ko is built
add_dependencies(dnbd3 dnbd3-generate-version)

set(CHECKPATCH_IGNORE_WARNINGS "NEW_TYPEDEFS"
                               "MSLEEP"
                               "CONSTANT_COMPARISON"
                               "DEEP_INDENTATION"
                               "PREFER_PR_LEVEL"
                               "LINUX_VERSION_CODE"
                               "JIFFIES_COMPARISON"
                               "KREALLOC_ARG_REUSE")

add_kernel_linter(dnbd3-lint "${CHECKPATCH_IGNORE_WARNINGS}"
                             "${KERNEL_MODULE_DNBD3_SOURCE_FILES}"
                             "${KERNEL_MODULE_DNBD3_HEADER_FILES}")
add_kernel_linter_fix(dnbd3-lint-fix "${CHECKPATCH_IGNORE_WARNINGS}"
                                     "${KERNEL_MODULE_DNBD3_SOURCE_FILES}"
                                     "${KERNEL_MODULE_DNBD3_HEADER_FILES}")

add_linter_fix(dnbd3-lint-fix-clang "${KERNEL_MODULE_DNBD3_SOURCE_FILES}"
                                    "${KERNEL_MODULE_DNBD3_HEADER_FILES}")
