cmake_minimum_required(VERSION 3.10)

# include CMake macros
set(PROJECT_MODULES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
					  ${PROJECT_MODULES_DIR})

# define root CMake project
project(dnbd3
        DESCRIPTION "dnbd3 Linux kernel module, server, clients and utilities"
        LANGUAGES C)

# define project options to define build configuration
OPTION(DNBD3_KERNEL_MODULE "Build the dnbd3 Linux kernel module" ON)
OPTION(DNBD3_SERVER_FUSE "Enable FUSE-Integration for dnbd3-server" OFF)
OPTION(DNBD3_SERVER_AFL "Build dnbd3-server for usage with afl-fuzz" OFF)
OPTION(DNBD3_SERVER_DEBUG_LOCKS "Add lock debugging code to dnbd3-server" OFF)
OPTION(DNBD3_SERVER_DEBUG_THREADS "Add thread debugging code to dnbd3-server" OFF)
OPTION(DNBD3_RELEASE_HARDENING "Harden dnbd3 programs in Release build configuration" OFF)

# set supported build configurations
set(CMAKE_CONFIGURATION_TYPES Debug Release)

# set compilation in debug mode as default configuration
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
    message(STATUS "Build type is not set. Defaulting to ${CMAKE_BUILD_TYPE} build!")
endif()

# search for required packages
find_package(Git)
find_package(Threads)
find_package(Fuse)

# abort if a required package is not available
if(NOT GIT_FOUND)
	message(FATAL_ERROR "No Git found, can't determine dnbd3 project version number!")
endif(NOT GIT_FOUND)
if(NOT THREADS_FOUND)
	message(FATAL_ERROR "No threads found, can't build dnbd3 project!")
endif(NOT THREADS_FOUND)
if(NOT FUSE_FOUND)
	message(FATAL_ERROR "No Fuse found, can't build dnbd3 project!")
endif(NOT FUSE_FOUND)

# check for system and enable or disable built of Linux kernel module
if(UNIX AND CMAKE_SYSTEM_NAME MATCHES "Linux")
    # set Linux kernel directories
    set(KERNEL_BUILD_DIR "/lib/modules/${CMAKE_SYSTEM_VERSION}/build"
        CACHE PATH "Path to Linux kernel modules to compile against")
    set(KERNEL_INSTALL_DIR "/lib/modules/${CMAKE_SYSTEM_VERSION}/extra"
        CACHE PATH "Path to install Linux kernel modules")

    # print configured settings
    message(STATUS "Path to Linux kernel modules to compile against is " ${KERNEL_BUILD_DIR})
    message(STATUS "Path to install Linux kernel modules is " ${KERNEL_INSTALL_DIR})

    # include Linux kernel version related macros
    include(KernelVersion)
else(UNIX AND CMAKE_SYSTEM_NAME MATCHES "Linux")
    # disable build of the dnbd3 Linux kernel module on a system other than Linux, eg. FreeBSD
    message(STATUS "Detected BSD System: Disable build of the dnbd3 Linux kernel module")
    set(DNBD3_KERNEL_MODULE OFF)
endif(UNIX AND CMAKE_SYSTEM_NAME MATCHES "Linux")

# include project version related macros
include(ProjectVersion)

# set include directories
set(PROJECT_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/inc)
set(PROJECT_INCLUDE_TMP_DIR ${CMAKE_CURRENT_BINARY_DIR}/inc)
include_directories(${PROJECT_INCLUDE_DIR})

# generate project version C header file from template
# exposes dnbd3-generate-version and dnbd3-version target
gen_project_version(${PROJECT_INCLUDE_DIR}/dnbd3/version.h.in ${PROJECT_INCLUDE_TMP_DIR}/dnbd3/version.h)

# add compile option to handle files greater than 2GB on a 32bit system
add_definitions(-D_FILE_OFFSET_BITS=64)

# define global C flags for compilation
set(CMAKE_C_FLAGS "-std=c11")

# enable all error warnings in Debug build configuration
set(CMAKE_C_FLAGS_DEBUG "-Wall -Wextra -Wpedantic -Wconversion -Wformat -Wformat-security -Werror=format-security")
set(CMAKE_C_FLAGS_RELEASE "-Wno-error")

# set compilation optimization
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -Og -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG")

if(DNBD3_RELEASE_HARDENING)
	# harden Release builds with specific C flags
	set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -mfunction-return=thunk -mindirect-branch=thunk")
endif(DNBD3_RELEASE_HARDENING)

# add all dnbd3 related projects from the source code directory
add_subdirectory(src)

# install config files into sample directory
file(GLOB DNBD3_CONF_FILES "${CMAKE_CURRENT_SOURCE_DIR}/conf/*")
install(FILES ${DNBD3_CONF_FILES} DESTINATION /etc/dnbd3-server/sample)
