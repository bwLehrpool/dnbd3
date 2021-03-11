cmake_minimum_required(VERSION 3.10)

# set the project name
project(picohttpparser
        LANGUAGES C)

set(PICOHTTPPARSER_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/picohttpparser.c)
set(PICOHTTPPARSER_HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/picohttpparser.h)

add_library(picohttpparser STATIC ${PICOHTTPPARSER_SOURCE_FILES})
target_include_directories(picohttpparser PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
