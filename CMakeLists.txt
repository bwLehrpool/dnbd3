################################################################################
# GENERAL                                                                      #
################################################################################

PROJECT(dnbd3 C)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6.2)
IF (CMAKE_BUILD_TYPE STREQUAL "")
	SET(CMAKE_BUILD_TYPE Debug)
ENDIF()

SET(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Path prefix for system installation")
OPTION(BUILD_FUSE_CLIENT "Build dnbd3 fuse client" ON)
OPTION(BUILD_SERVER "Build dnbd3 server" ON)
OPTION(BUILD_STRESSTEST "Build dnbd3 stress testing tool" OFF)
SET(EXTRA_C_FLAGS "" CACHE STRING "Additional options to pass to compiler")

OPTION(SERVER_FOR_AFL "Build dnbd3-server for usage with afl-fuzz" OFF)

# Is there a non-retarded way to check if build type is debug or release?
# When specifying, it is case insensitive, so DeBuG would also enable debug builds,
# but in cmake, we can only do case sensitive matches... :/
string( TOLOWER "${CMAKE_BUILD_TYPE}" bt_lower )
if (NOT bt_lower MATCHES "^(debug|release)$")
	message( FATAL_ERROR "Build type needs to be either Debug or Release" )
endif()

message( "Build Type selected: ${CMAKE_BUILD_TYPE}" )

IF(CMAKE_SYSTEM_NAME MATCHES "BSD")
	message("Detected *BSD System: disable build of Kernel Module.")
	SET(BUILD_KERNEL_MODULE False)
ELSE()
	OPTION(BUILD_KERNEL_MODULE "Build the dnbd3 Linux kernel module" ON)
ENDIF()

if(CMAKE_C_COMPILER MATCHES "clang")
	message( "Using clang flags." )
	SET(CMAKE_C_FLAGS_DEBUG "-std=c11 -O1 -fno-omit-frame-pointer -g -Wall -Wextra -Wpedantic -Wno-unused-result -D_GNU_SOURCE -D_DEBUG -Wno-multichar -fno-strict-aliasing ${EXTRA_C_FLAGS}")
	SET(CMAKE_C_FLAGS_RELEASE "-std=c11 -O2 -Wno-unused-result -D_GNU_SOURCE -DNDEBUG -Wno-multichar -fno-strict-aliasing ${EXTRA_C_FLAGS}")
elseif (CMAKE_C_COMPILER MATCHES "(cc-)|(cc$)")
	message( "Using (g)cc flags." )
	SET(CMAKE_C_FLAGS_DEBUG "-std=c11 -O0 -g -Wall -Wextra -Wpedantic -Wconversion -Wno-sign-conversion -D_GNU_SOURCE -D_DEBUG -Wno-multichar -fno-strict-aliasing ${EXTRA_C_FLAGS}")
	SET(CMAKE_C_FLAGS_RELEASE "-std=c11 -O2 -Wno-unused-result -D_GNU_SOURCE -DNDEBUG -Wno-multichar -fno-strict-aliasing ${EXTRA_C_FLAGS}")
else()
	message( FATAL_ERROR "Could not determine compiler type." )
endif()
#SET(CMAKE_CXX_FLAGS_DEBUG "-std=c99 -O0 -g -Wall -Wno-unused-result -D_GNU_SOURCE -D_DEBUG")
#SET(CMAKE_CXX_FLAGS_RELEASE "-std=c99 -O2 -Wno-unused-result -D_GNU_SOURCE -DNDEBUG" )

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

ADD_DEFINITIONS(-D_FILE_OFFSET_BITS=64)
ADD_DEFINITIONS(-DWITH_IPV6)

FIND_PACKAGE(Threads)

SET(DO_ABORT False)

message( " *************************************************" )
if(BUILD_FUSE_CLIENT)
	FIND_PACKAGE(Fuse)
	if(NOT FUSE_FOUND)
		message( " *** No fuse dev libs found, can't build dnbd3-fuse" )
		SET(DO_ABORT True)
	endif()
	if(NOT THREADS_FOUND)
		message( " *** No threads found, can't build dnbd3-fuse" )
		SET(DO_ABORT True)
	endif()
endif()
if(BUILD_SERVER)
	FIND_PACKAGE(Jansson)
	if(NOT THREADS_FOUND)
		message( " *** No threads found, can't build dnbd3-server" )
		SET(DO_ABORT True)
	endif()
	if(NOT JANSSON_FOUND)
		message( " *** No jansson lib found, can't build dnbd3-server" )
		SET(DO_ABORT True)
	endif()
endif()
if(BUILD_STRESSTEST)
	if(NOT THREADS_FOUND)
		message( " *** No threads found, can't build dnbd3-bench" )
		SET(DO_ABORT True)
	endif()
endif()
message( " *************************************************" )
if(DO_ABORT)
	message( FATAL_ERROR "Aborting." )
endif()

#SET(FUSE_INCLUDE_DIR "")
#SET(JANSSON_INCLUDE_DIR "")

################################################################################
# VERSION HEADER                                                               #
################################################################################

FILE(WRITE ${CMAKE_BINARY_DIR}/version.cmake
"EXECUTE_PROCESS(
	COMMAND \${CMD}
	OUTPUT_VARIABLE VERSION
	OUTPUT_STRIP_TRAILING_WHITESPACE
 )
 CONFIGURE_FILE(\${SRC} \${DST} @ONLY)
")
ADD_CUSTOM_TARGET(
	version
	${CMAKE_COMMAND} -D SRC=${CMAKE_SOURCE_DIR}/src/version.c.in
						-D DST=${CMAKE_BINARY_DIR}/version.c
						-D CMD=${CMAKE_SOURCE_DIR}/get-version.sh
						-P ${CMAKE_BINARY_DIR}/version.cmake
)

## This is required if you're not building the kernel module
## TODO: Find a nicer way to avoid parent includes,
## especially the ../version.h -> version.c -> version.h cycle
FILE(GLOB COMMON_HEADER_FILES src/*.h)
FOREACH(COMMON_HEADER_FILE ${COMMON_HEADER_FILES})
	CONFIGURE_FILE(${COMMON_HEADER_FILE} ${CMAKE_BINARY_DIR} COPYONLY)
ENDFOREACH( COMMON_HEADER_FILE )


################################################################################
# CLIENT                                                                       #
################################################################################

if(BUILD_KERNEL_MODULE)
	INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR})
	FILE(GLOB_RECURSE CLIENT_SRCS src/client/*.c)
	ADD_EXECUTABLE(dnbd3-client ${CLIENT_SRCS})
	TARGET_LINK_LIBRARIES(dnbd3-client)
	ADD_DEPENDENCIES(dnbd3-client version)
	INSTALL(TARGETS dnbd3-client RUNTIME DESTINATION sbin)
ENDIF()


################################################################################
# SERVER                                                                       #
################################################################################

if(BUILD_SERVER)
	IF(SERVER_FOR_AFL)
		message(" ######################## Building server for AFL mode - will be useless otherwise!")
		ADD_DEFINITIONS(-DAFL_MODE)
	ENDIF()
	INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR} ${JANSSON_INCLUDE_DIR})
	FILE(GLOB SERVER_SRCS src/server/*.c src/shared/*.c src/server/picohttpparser/*.c)
	ADD_EXECUTABLE(dnbd3-server ${SERVER_SRCS})
	TARGET_LINK_LIBRARIES(dnbd3-server ${CMAKE_THREAD_LIBS_INIT} ${JANSSON_LIBRARIES})
	if(UNIX AND NOT APPLE)
		target_link_libraries(dnbd3-server rt)
	endif()
	ADD_DEPENDENCIES(dnbd3-server version)
	INSTALL(TARGETS dnbd3-server RUNTIME DESTINATION sbin)
endif()



################################################################################
# FUSE                                                                         #
################################################################################

if(BUILD_FUSE_CLIENT)
	INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR} ${FUSE_INCLUDE_DIR})
	FILE(GLOB FUSE_SRCS src/fuse/*.c src/shared/*.c)
	ADD_EXECUTABLE(dnbd3-fuse ${FUSE_SRCS})
	TARGET_LINK_LIBRARIES(dnbd3-fuse ${CMAKE_THREAD_LIBS_INIT} ${FUSE_LIBRARIES})
	ADD_DEPENDENCIES(dnbd3-fuse version)
	INSTALL(TARGETS dnbd3-fuse RUNTIME DESTINATION bin)
endif()

################################################################################
# STRESSTEST                                                                   #
################################################################################

if(BUILD_STRESSTEST)
	FILE(GLOB BENCH_SRCS src/bench/*.c src/shared/*.c)
	ADD_EXECUTABLE(dnbd3-bench ${BENCH_SRCS})
	TARGET_LINK_LIBRARIES(dnbd3-bench ${CMAKE_THREAD_LIBS_INIT})
	ADD_DEPENDENCIES(dnbd3-bench version)
	INSTALL(TARGETS dnbd3-bench RUNTIME DESTINATION bin)
endif()

################################################################################
# MODULE                                                                       #
################################################################################

IF(BUILD_KERNEL_MODULE)
	SET(MODULE_NAME dnbd3)
	SET(MODULE_FILE ${MODULE_NAME}.ko)
	FILE(GLOB MODULE_SOURCE_FILES src/kernel/*.c src/serialize.c)
	FILE(GLOB MODULE_HEADER_FILES src/kernel/*.h)

	SET(KERNEL_DIR "" CACHE PATH "Path to kernel sources to compile against")
	IF(KERNEL_DIR STREQUAL "")
		SET(KERNEL_DIR "/lib/modules/${CMAKE_SYSTEM_VERSION}/build")
	ENDIF()

	SET(KBUILD_COMMAND ${CMAKE_MAKE_PROGRAM} -C ${KERNEL_DIR}
		M=${CMAKE_BINARY_DIR} modules
	)

	CONFIGURE_FILE(Kbuild.in ${CMAKE_BINARY_DIR}/Kbuild)

	FOREACH(MODULE_SOURCE_FILE ${MODULE_SOURCE_FILES})
		CONFIGURE_FILE(${MODULE_SOURCE_FILE} ${CMAKE_BINARY_DIR} COPYONLY)
	ENDFOREACH( MODULE_SOURCE_FILE )

	FOREACH(MODULE_HEADER_FILE ${MODULE_HEADER_FILES})
		CONFIGURE_FILE(${MODULE_HEADER_FILE} ${CMAKE_BINARY_DIR} COPYONLY)
	ENDFOREACH( MODULE_HEADER_FILE )

	ADD_CUSTOM_COMMAND(
		OUTPUT ${CMAKE_BINARY_DIR}/${MODULE_FILE}
		COMMAND ${KBUILD_COMMAND}
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
		DEPENDS ${MODULE_SOURCE_FILES} Kbuild.in
		VERBATIM
	)

	ADD_CUSTOM_TARGET(${MODULE_NAME} ALL DEPENDS ${CMAKE_BINARY_DIR}/${MODULE_FILE})

	INSTALL(FILES ${CMAKE_BINARY_DIR}/${MODULE_NAME}.ko
		DESTINATION /lib/modules/${CMAKE_SYSTEM_VERSION}/kernel/drivers/block
		PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
	)

	INSTALL(CODE "EXECUTE_PROCESS(COMMAND depmod -a)")
ENDIF()


#
# Other install files
#

FILE(GLOB conf_files "${CMAKE_CURRENT_SOURCE_DIR}/conf/*")
INSTALL(FILES ${conf_files} DESTINATION /etc/dnbd3-server/sample/)

