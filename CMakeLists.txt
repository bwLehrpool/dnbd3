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
OPTION(DNBD3_CLIENT_FUSE "Enable build of dnbd3-fuse" ON)
OPTION(DNBD3_SERVER "Enable build of dnbd3-server" ON)
OPTION(DNBD3_SERVER_FUSE "Enable FUSE-Integration for dnbd3-server" OFF)
OPTION(DNBD3_SERVER_AFL "Build dnbd3-server for usage with afl-fuzz" OFF)
OPTION(DNBD3_SERVER_DEBUG_LOCKS "Add lock debugging code to dnbd3-server" OFF)
OPTION(DNBD3_SERVER_DEBUG_THREADS "Add thread debugging code to dnbd3-server" OFF)
OPTION(DNBD3_RELEASE_HARDEN "Compile dnbd3 programs in Release build with code hardening options" OFF)
OPTION(DNBD3_PACKAGE_DOCKER "Enable packaging of Docker image" OFF)
OPTION(DNBD3_LINT "Enable source code linting and formatting with clang-format" OFF)

# set supported build configurations
set(CMAKE_CONFIGURATION_TYPES Debug Release)

# set compilation in debug mode as default configuration
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
    message(STATUS "Build type is not set. Defaulting to ${CMAKE_BUILD_TYPE} build!")
endif(NOT CMAKE_BUILD_TYPE)

# search for required packages
find_package(Git REQUIRED)
find_package(Threads REQUIRED)

# include project version and build type related macros
include(Version)
include(Build)
if(DNBD3_LINT)
    include(Lint)
else()
    macro(add_linter LINT_NAME LINT_SOURCE_FILES)
    endmacro()
    macro(add_linter_fix LINT_NAME LINT_SOURCE_FILES)
    endmacro()
    macro(add_kernel_linter LINT_NAME LINT_SOURCE_FILES)
    endmacro()
    macro(add_kernel_linter_fix LINT_NAME LINT_SOURCE_FILES)
    endmacro()
endif(DNBD3_LINT)

# check for system and enable or disable built of Linux kernel module
if(DNBD3_KERNEL_MODULE AND UNIX AND CMAKE_SYSTEM_NAME MATCHES "Linux")
    # require Linux kernel headers
    find_package(KernelHeaders REQUIRED)

    # print configured settings
    message(STATUS "Path to Linux kernel modules to compile against is " ${KERNEL_BUILD_DIR})
    message(STATUS "Path to install Linux kernel modules is " ${KERNEL_INSTALL_DIR})
else(DNBD3_KERNEL_MODULE AND UNIX AND CMAKE_SYSTEM_NAME MATCHES "Linux")
    # disable build of the dnbd3 Linux kernel module on a system other than Linux, eg. FreeBSD
    message(STATUS "Detected non-Linux system: Disable build of the dnbd3 Linux kernel module")
    set(DNBD3_KERNEL_MODULE OFF)
endif(DNBD3_KERNEL_MODULE AND UNIX AND CMAKE_SYSTEM_NAME MATCHES "Linux")

# set include directories
set(PROJECT_GEN_DIR ${CMAKE_BINARY_DIR}/generated)
set(PROJECT_INCLUDE_DIR_PREFIX inc)
set(PROJECT_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/${PROJECT_INCLUDE_DIR_PREFIX})
set(PROJECT_INCLUDE_GEN_DIR ${PROJECT_GEN_DIR}/${PROJECT_INCLUDE_DIR_PREFIX})
include_directories(${PROJECT_INCLUDE_DIR})

# get all global header files for the linter
set(DNBD3_HEADER_FILES ${PROJECT_INCLUDE_DIR}/dnbd3/build.h.in
                       ${PROJECT_INCLUDE_DIR}/dnbd3/config/client.h
                       ${PROJECT_INCLUDE_DIR}/dnbd3/config.h
                       ${PROJECT_INCLUDE_DIR}/dnbd3/config/server.h
                       ${PROJECT_INCLUDE_DIR}/dnbd3/shared/crc32.h
                       ${PROJECT_INCLUDE_DIR}/dnbd3/shared/fdsignal.h
                       ${PROJECT_INCLUDE_DIR}/dnbd3/shared/log.h
                       ${PROJECT_INCLUDE_DIR}/dnbd3/shared/protocol.h
                       ${PROJECT_INCLUDE_DIR}/dnbd3/shared/serialize.h
                       ${PROJECT_INCLUDE_DIR}/dnbd3/shared/sockhelper.h
                       ${PROJECT_INCLUDE_DIR}/dnbd3/shared/timing.h
                       ${PROJECT_INCLUDE_DIR}/dnbd3/types.h
                       ${PROJECT_INCLUDE_DIR}/dnbd3/version.h.in)

# add linter for header files
add_linter(dnbd3-headers-lint "${DNBD3_HEADER_FILES}")
add_linter_fix(dnbd3-headers-lint-fix "${DNBD3_HEADER_FILES}")

# generate project version C header file from template
# exposes dnbd3-generate-version and dnbd3-version target
set(INCLUDE_VERSION_HEADER ${PROJECT_INCLUDE_DIR}/dnbd3/version.h)
set(INCLUDE_VERSION_HEADER_TEMPLATE ${PROJECT_INCLUDE_DIR}/dnbd3/version.h.in)
set(INCLUDE_VERSION_HEADER_GENERATE ${PROJECT_INCLUDE_GEN_DIR}/dnbd3/version.h)
set(INCLUDE_VERSION_HEADER_GENERATE_PREFIX ${PROJECT_INCLUDE_DIR_PREFIX}/dnbd3)
gen_project_version(${INCLUDE_VERSION_HEADER} ${INCLUDE_VERSION_HEADER_TEMPLATE} ${INCLUDE_VERSION_HEADER_GENERATE} ${GIT_EXECUTABLE} ${CMAKE_SOURCE_DIR})

# generate project build type C header file from template
# exposes dnbd3-generate-build and dnbd3-build target
set(INCLUDE_BUILD_HEADER_TEMPLATE ${PROJECT_INCLUDE_DIR}/dnbd3/build.h.in)
set(INCLUDE_BUILD_HEADER_GENERATE ${PROJECT_INCLUDE_GEN_DIR}/dnbd3/build.h)
gen_build_type(${INCLUDE_BUILD_HEADER_TEMPLATE} ${INCLUDE_BUILD_HEADER_GENERATE})

# add compile option to handle files greater than 2GB on a 32bit system
add_definitions(-D_FILE_OFFSET_BITS=64)

# define global C flags for compilation
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")

# enable all error warnings in Debug build configuration
set(CMAKE_C_FLAGS_DEBUG "-Wall -Wextra -Wpedantic -Wconversion -Wformat -Wformat-security -Werror=format-security -Wno-sign-conversion")
set(CMAKE_C_FLAGS_RELEASE "-Wno-error")

# set compilation optimization
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -Og -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG")

if(DNBD3_RELEASE_HARDEN AND CMAKE_BUILD_TYPE MATCHES "Release")
	# harden builds with specific C flags
	set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -D_FORTIFY_SOURCE=2 -fstack-protector-all -fstack-clash-protection")
    # set specific hardened linker flags
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro,-z,now,-z,defs -pie")
    # print status message of configuration
    message(STATUS "Set compilation of DNBD3 with hardened code options - done")
else(DNBD3_RELEASE_HARDEN AND CMAKE_BUILD_TYPE MATCHES "Release")
    # print status message of disabled configuration
    message(STATUS "Disabled compilation of dnbd3 with hardened code options - done")
endif(DNBD3_RELEASE_HARDEN AND CMAKE_BUILD_TYPE MATCHES "Release")

# define packaging if Release build is enabled
if(CMAKE_BUILD_TYPE MATCHES Release)
    # get version source package or Git repository
    get_repository_version(REPOSITORY_VERSION ${INCLUDE_VERSION_HEADER} ${CMAKE_BUILD_TYPE} ${GIT_EXECUTABLE} ${CMAKE_SOURCE_DIR})

    # define project version
    if(KernelHeaders_VERSION)
        set(REPOSITORY_VERSION_FULL ${REPOSITORY_VERSION}-${KernelHeaders_VERSION})
    else(KernelHeaders_VERSION)
        set(REPOSITORY_VERSION_FULL ${REPOSITORY_VERSION})
    endif(KernelHeaders_VERSION)

    set(CPACK_GENERATOR "DEB;RPM;TGZ")
    set(CPACK_PACKAGE_NAME ${CMAKE_PROJECT_NAME})
    set(CPACK_MONOLITHIC_INSTALL True)
    set(CPACK_PACKAGE_VERSION ${REPOSITORY_VERSION})
    set(CPACK_PACKAGE_VERSION_FULL ${REPOSITORY_VERSION_FULL})
    set(CPACK_PACKAGE_SECTION admin)
    set(CPACK_PACKAGE_VENDOR "University of Freiburg")
    set(CPACK_PACKAGE_CONTACT "Christian Rößler <christian.roessler@rz.uni-freiburg.de>")
    set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/bwLehrpool/dnbd3")
    set(CPACK_PACKAGE_CHECKSUM SHA256)
    set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}_${REPOSITORY_VERSION_FULL}_${CMAKE_SYSTEM_PROCESSOR})
    set(CPACK_SOURCE_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_source)
    set(CPACK_STRIP_FILES True)
    set(CPACK_PACKAGE_RELOCATABLE False)
    set(CPACK_SET_DESTDIR True)
    set(CMAKE_INSTALL_PREFIX "/usr")
    set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
    set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/COPYING)
    set(CPACK_RESOURCE_FILE_README ${CMAKE_CURRENT_SOURCE_DIR}/README.md)

    # set DEB generator specific packaging options
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6, libfuse2, libjansson4, libatomic1")
    if(DNBD3_KERNEL_MODULE)
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postinst "depmod -a\n")
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postrm "depmod -a\n")
        set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postinst
                                               ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postrm)
    endif(DNBD3_KERNEL_MODULE)

    # set RPM generator specific packaging options
    set(CPACK_RPM_PACKAGE_REQUIRES "glibc, fuse-libs, jansson, libatomic")
    set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/lib"
                                                      "/lib/modules"
                                                      "/lib/modules/${CMAKE_SYSTEM_VERSION}"
                                                      "/lib/modules/${CMAKE_SYSTEM_VERSION}/extra"
                                                      "/etc"
                                                      "/usr"
                                                      "/usr/lib"
                                                      "/usr/lib/systemd"
                                                      "/usr/lib/systemd/system")
    if(DNBD3_KERNEL_MODULE)
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/package/rpm/post "depmod -a\n")
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/package/rpm/postun "depmod -a\n")
        set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE ${CMAKE_CURRENT_BINARY_DIR}/package/rpm/post)
        set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE ${CMAKE_CURRENT_BINARY_DIR}/package/rpm/postun)
    endif(DNBD3_KERNEL_MODULE)

    # configure source packaging
    set(CPACK_SOURCE_GENERATOR "TGZ;ZIP")
    set(CPACK_SOURCE_INSTALLED_DIRECTORIES "${CMAKE_SOURCE_DIR}" "/"
                                           "${PROJECT_GEN_DIR}"  "/")
    set(CPACK_SOURCE_IGNORE_FILES "/build/"
                                  "/.git/"
                                  "/.github/"
                                  ".gitignore"
                                  "version.h.in")

    # include CPack functionality
    include(CPack)

    # prepare source packaging
    add_custom_command(OUTPUT ${INCLUDE_VERSION_HEADER}
                       COMMAND ${CMAKE_COMMAND} -D VERSION_HEADER_INPUT_FILE=${INCLUDE_VERSION_HEADER_GENERATE}
                                                -D VERSION_HEADER_OUTPUT_FILE=${INCLUDE_VERSION_HEADER}
                                                -P ${PROJECT_MODULES_DIR}/PreVersionPackaging.cmake
                       COMMENT "Prepare version.h"
                       DEPENDS dnbd3-generate-version)

    # main source packaging
    add_custom_target(package_source_main
                      COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target package_source
                      DEPENDS ${INCLUDE_VERSION_HEADER}
                      VERBATIM
                      USES_TERMINAL)

    # post source packaging and exported target to build source packages
    add_custom_target(source
                      COMMAND ${CMAKE_COMMAND} -D VERSION_HEADER_INPUT_FILE=${INCLUDE_VERSION_HEADER_GENERATE}
                                               -D VERSION_HEADER_OUTPUT_FILE=${INCLUDE_VERSION_HEADER}
                                               -P ${PROJECT_MODULES_DIR}/PostVersionPackaging.cmake
                      COMMENT "Cleanup version.h"
                      DEPENDS package_source_main)

    # include target to make docker image
    if(NOT DNBD3_KERNEL_MODULE AND DNBD3_SERVER AND DNBD3_PACKAGE_DOCKER)
        find_package(Docker REQUIRED)
        include(DockerImage)

        set(DOCKER_TAG ${CPACK_PACKAGE_NAME}:${REPOSITORY_VERSION_FULL})

        # define Ubuntu docker image
        set(DOCKER_FILE_UBUNTU ${CMAKE_SOURCE_DIR}/pkg/docker/ubuntu-20-04_dockerfile)
        set(PACKAGE_FILE_UBUNTU ${CPACK_PACKAGE_NAME}_${REPOSITORY_VERSION_FULL}_${CMAKE_SYSTEM_PROCESSOR}.deb)
        set(DOCKER_IMAGE_UBUNTU ${CPACK_PACKAGE_NAME}_${REPOSITORY_VERSION_FULL}_${CMAKE_SYSTEM_PROCESSOR}_ubuntu-20-04_docker.tar)
        add_docker_image(docker-ubuntu-20-04 ${DOCKER_IMAGE_UBUNTU} ${DOCKER_FILE_UBUNTU} ${DOCKER_TAG} ${PACKAGE_FILE_UBUNTU} ${CMAKE_BINARY_DIR})

        # define Archlinux docker image
        set(DOCKER_FILE_ARCHLINUX ${CMAKE_SOURCE_DIR}/pkg/docker/archlinux_dockerfile)
        set(PACKAGE_FILE_ARCHLINUX ${CPACK_PACKAGE_NAME}_${REPOSITORY_VERSION_FULL}_${CMAKE_SYSTEM_PROCESSOR}.tar.gz)
        set(DOCKER_IMAGE_ARCHLINUX ${CPACK_PACKAGE_NAME}_${REPOSITORY_VERSION_FULL}_${CMAKE_SYSTEM_PROCESSOR}_archlinux_docker.tar)
        add_docker_image(docker-archlinux ${DOCKER_IMAGE_ARCHLINUX} ${DOCKER_FILE_ARCHLINUX} ${DOCKER_TAG} ${PACKAGE_FILE_ARCHLINUX} ${CMAKE_BINARY_DIR})
    endif(NOT DNBD3_KERNEL_MODULE AND DNBD3_SERVER AND DNBD3_PACKAGE_DOCKER)
endif(CMAKE_BUILD_TYPE MATCHES Release)

# add all dnbd3 related projects from the source code directory
add_subdirectory(src)

# add configuration and operational files for packaging purposes
add_subdirectory(pkg)
