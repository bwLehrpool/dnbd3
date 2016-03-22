################################################################################
# GENERAL                                                                      #
################################################################################

PROJECT(dnbd3 C)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6.2)
IF (CMAKE_BUILD_TYPE STREQUAL "")
	SET(CMAKE_BUILD_TYPE Debug)
ENDIF()

message( "Build Type selected: ${CMAKE_BUILD_TYPE}" )

SET(MAKE_KERNEL_MODULE True)
IF(CMAKE_SYSTEM_NAME MATCHES "BSD")
	message("Detected *BSD System: disable build of Kernel Module.")
	SET(CMAKE_INSTALL_PREFIX "/usr/local")
	SET(MAKE_KERNEL_MODULE False)
ENDIF()

if(CMAKE_C_COMPILER MATCHES "clang")
	message( "Using clang flags." )
	SET(CMAKE_C_FLAGS_DEBUG "-std=c99 -fsanitize=address -O1 -fno-omit-frame-pointer -g -Wall -Wno-unused-result -D_GNU_SOURCE -D_DEBUG -Wno-multichar -fno-strict-aliasing")
	SET(CMAKE_C_FLAGS_RELEASE "-std=c99 -O2 -Wno-unused-result -D_GNU_SOURCE -DNDEBUG -Wno-multichar -fno-strict-aliasing")
elseif (CMAKE_C_COMPILER MATCHES "(cc-)|(cc$)")
	message( "Using (g)cc flags." )
	SET(CMAKE_C_FLAGS_DEBUG "-std=c99 -O0 -g -Wall -Wextra -Wpedantic -D_GNU_SOURCE -D_DEBUG -Wno-multichar -fno-strict-aliasing")
	SET(CMAKE_C_FLAGS_RELEASE "-std=c99 -O2 -Wno-unused-result -D_GNU_SOURCE -DNDEBUG -Wno-multichar -fno-strict-aliasing")
else()
	message( FATAL_ERROR "Could not determine compiler type." )
endif()
#SET(CMAKE_CXX_FLAGS_DEBUG "-std=c99 -O0 -g -Wall -Wno-unused-result -D_GNU_SOURCE -D_DEBUG")
#SET(CMAKE_CXX_FLAGS_RELEASE "-std=c99 -O2 -Wno-unused-result -D_GNU_SOURCE -DNDEBUG" )

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

ADD_DEFINITIONS(-D_FILE_OFFSET_BITS=64)
ADD_DEFINITIONS(-DWITH_IPV6)

FIND_PACKAGE(Threads)
FIND_PACKAGE(Fuse)
FIND_PACKAGE(ZLIB)
FIND_PACKAGE(Jansson)

SET(MAKE_SERVER True)

message( " *************************************************" )
if(NOT FUSE_FOUND)
	message( " *** No fuse dev libs found, won't build dnbd3-fuse" )
	SET(FUSE_INCLUDE_DIR "")
endif()
if(NOT THREADS_FOUND)
	message( " *** No threads found, won't build dnbd3-server" )
	SET(MAKE_SERVER False)
endif()
if(NOT ZLIB_FOUND)
	message( " *** No zlib found, won't build dnbd3-server" )
	SET(ZLIB_INCLUDE_DIR "")
	SET(MAKE_SERVER False)
endif()
if(NOT JANSSON_FOUND)
	message( " *** No jansson lib found, won't build dnbd3-server" )
	SET(JANSSON_INCLUDE_DIR "")
	SET(MAKE_SERVER False)
endif()
message( " *************************************************" )

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR} ${ZLIB_INCLUDE_DIR} ${FUSE_INCLUDE_DIR} ${JANSSON_INCLUDE_DIR})

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

if(MAKE_KERNEL_MODULE)
	FILE(GLOB_RECURSE CLIENT_SRCS src/client/*.c)
	ADD_EXECUTABLE(dnbd3-client ${CLIENT_SRCS})
	TARGET_LINK_LIBRARIES(dnbd3-client)
	ADD_DEPENDENCIES(dnbd3-client version)
	INSTALL(TARGETS dnbd3-client RUNTIME DESTINATION sbin)
ENDIF()


################################################################################
# SERVER                                                                       #
################################################################################

if(MAKE_SERVER)
	FILE(GLOB SERVER_SRCS src/server/*.c src/shared/*.c)
	ADD_EXECUTABLE(dnbd3-server ${SERVER_SRCS})
	TARGET_LINK_LIBRARIES(dnbd3-server ${CMAKE_THREAD_LIBS_INIT} ${ZLIB_LIBRARIES} ${JANSSON_LIBRARIES})
	if(UNIX AND NOT APPLE)
		target_link_libraries(dnbd3-server rt)
	endif()
	ADD_DEPENDENCIES(dnbd3-server version)
	INSTALL(TARGETS dnbd3-server RUNTIME DESTINATION sbin)
endif()



################################################################################
# FUSE                                                                         #
################################################################################

if(FUSE_FOUND)
	FILE(GLOB FUSE_SRCS src/fuse/*.c src/shared/*.c)
	ADD_EXECUTABLE(dnbd3-fuse ${FUSE_SRCS})
	TARGET_LINK_LIBRARIES(dnbd3-fuse ${CMAKE_THREAD_LIBS_INIT} ${FUSE_LIBRARIES})
	ADD_DEPENDENCIES(dnbd3-fuse version)
	INSTALL(TARGETS dnbd3-fuse RUNTIME DESTINATION bin)
endif()



################################################################################
# MODULE                                                                       #
################################################################################

IF(MAKE_KERNEL_MODULE)
	SET(MODULE_NAME dnbd3)
	SET(MODULE_FILE ${MODULE_NAME}.ko)
	FILE(GLOB MODULE_SOURCE_FILES src/kernel/*.c src/serialize.c)
	FILE(GLOB MODULE_HEADER_FILES src/kernel/*.h)

	SET(KERNEL_DIR "/lib/modules/${CMAKE_SYSTEM_VERSION}/build")

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
INSTALL(FILES ${conf_files} DESTINATION /etc/dnbd3/)

