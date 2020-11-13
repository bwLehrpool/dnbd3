cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-server
        LANGUAGES C)

# find Jansson package required by the dnbd3-server
find_package(Jansson)
if(NOT JANSSON_FOUND)
    message(FATAL_ERROR "*** No jansson lib found, can't build dnbd3-server!")
endif(NOT JANSSON_FOUND)

# add compile option to enable enhanced POSIX features
add_definitions(-D_GNU_SOURCE)

if(DNBD3_SERVER_AFL)
    # check if DNBD3_RELEASE_HARDEN is disabled
    if(DNBD3_RELEASE_HARDEN)
        message(FATAL_ERROR "DNBD3_SERVER_AFL can only be enabled if DNBD3_RELEASE_HARDEN is disabled")
    endif(DNBD3_RELEASE_HARDEN)

    # build dnbd3-server with AFL support
    message(STATUS "Building dnbd3-server with AFL support")
    add_definitions(-DDNBD3_SERVER_AFL)

    # change compiler for dnbd3-server sources if AFL enabled
    include(CheckAFLCCompiler)
    check_afl_c_compiler(AFL_C_COMPILER AFL_C_COMPILER_NAME ${CMAKE_C_COMPILER} ${CMAKE_C_COMPILER_ID})
    if(AFL_C_COMPILER)
        message(STATUS "Check for working AFL C compiler: ${AFL_C_COMPILER} - done")
        # change C compiler to a corresponding AFL C compiler
        set(CMAKE_C_COMPILER "${AFL_C_COMPILER}")
    else(AFL_C_COMPILER)
        # no corresponding AFL C compiler found
        message(STATUS "Check for working AFL C compiler: ${AFL_C_COMPILER_NAME} - failed")
        message(FATAL_ERROR "No corresponding AFL C compiler ${AFL_C_COMPILER_NAME} was found for the C compiler ${CMAKE_C_COMPILER}!")
    endif(AFL_C_COMPILER)
endif(DNBD3_SERVER_AFL)

add_executable(dnbd3-server ${CMAKE_CURRENT_SOURCE_DIR}/altservers.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/fileutil.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/fuse.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/globals.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/helper.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/image.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/ini.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/integrity.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/locks.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/net.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/picohttpparser/picohttpparser.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/reference.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/rpc.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/server.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/threadpool.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/uplink.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/urldecode.c)
target_include_directories(dnbd3-server PRIVATE ${JANSSON_INCLUDE_DIR})
target_link_libraries(dnbd3-server dnbd3-version dnbd3-build dnbd3-shared ${CMAKE_THREAD_LIBS_INIT} ${JANSSON_LIBRARIES})

if(DNBD3_SERVER_FUSE)
    find_package(Fuse REQUIRED)
    # include Fuse headers and link with Fuse library
    target_compile_options(dnbd3-server PRIVATE -DDNBD3_SERVER_FUSE)
    target_include_directories(dnbd3-server PRIVATE ${FUSE_INCLUDE_DIRS})
    target_link_libraries(dnbd3-server ${FUSE_LIBRARIES})
endif(DNBD3_SERVER_FUSE)

if(UNIX AND NOT APPLE)
    # link dnbd3-server with librt if server is compiled for a Unix system
    target_link_libraries(dnbd3-server rt)
endif(UNIX AND NOT APPLE)

if(DNBD3_SERVER_DEBUG_LOCKS)
    # enable debugging of locks used in the dnbd3-server
    target_compile_options(dnbd3-server PRIVATE -DDNBD3_SERVER_DEBUG_LOCKS)
endif(DNBD3_SERVER_DEBUG_LOCKS)

if(DNBD3_SERVER_DEBUG_THREADS)
    # enable debugging of threads used in the dnbd3-server
    target_compile_options(dnbd3-server PRIVATE -DDNBD3_SERVER_DEBUG_THREADS)
endif(DNBD3_SERVER_DEBUG_THREADS)

install(TARGETS dnbd3-server RUNTIME DESTINATION bin
        COMPONENT server)
