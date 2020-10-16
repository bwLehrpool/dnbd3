cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-shared)

# add compile option to get POLLRDHUP support for signals
add_compile_options(-D_GNU_SOURCE)

add_library(dnbd3-shared STATIC ${CMAKE_CURRENT_SOURCE_DIR}/crc32.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/fdsignal.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/log.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/serialize.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/sockhelper.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/timing.c)
target_include_directories(dnbd3-shared PUBLIC ${PROJECT_INCLUDE_DIR})
