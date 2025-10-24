cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-shared
        LANGUAGES C)

# find atomic library required by dnbd3-shared
find_package(Stdatomic REQUIRED)
find_package(Libatomic REQUIRED)

# add compile option to get POLLRDHUP support for signals
add_definitions(-D_GNU_SOURCE)

if(DNBD3_SERVER_AFL)
    message(STATUS "Building dnbd3-shared with AFL support")
    add_definitions(-DDNBD3_SERVER_AFL)
endif(DNBD3_SERVER_AFL)

set(DNBD3_SHARED_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/crc32.c
                              ${CMAKE_CURRENT_SOURCE_DIR}/fdsignal.c
                              ${CMAKE_CURRENT_SOURCE_DIR}/log.c
                              ${CMAKE_CURRENT_SOURCE_DIR}/serialize.c
                              ${CMAKE_CURRENT_SOURCE_DIR}/sockhelper.c
                              ${CMAKE_CURRENT_SOURCE_DIR}/timing.c)
set(DNBD3_SHARED_HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/fdsignal.inc/eventfd.c
                              ${CMAKE_CURRENT_SOURCE_DIR}/fdsignal.inc/pipe64.c
                              ${CMAKE_CURRENT_SOURCE_DIR}/fdsignal.inc/pipe_malloc.c)

add_library(dnbd3-shared STATIC ${DNBD3_SHARED_SOURCE_FILES})
target_include_directories(dnbd3-shared PUBLIC ${PROJECT_INCLUDE_DIR})

add_linter(dnbd3-shared-lint "${DNBD3_SHARED_SOURCE_FILES}" "${DNBD3_SHARED_HEADER_FILES}")
add_linter_fix(dnbd3-shared-lint-fix "${DNBD3_SHARED_SOURCE_FILES}" "${DNBD3_SHARED_HEADER_FILES}")
