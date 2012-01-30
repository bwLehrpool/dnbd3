################################################################################
# GENERAL                                                                      #
################################################################################

PROJECT(dnbd3)
CMAKE_MINIMUM_REQUIRED(VERSION 2.8.0)

SET(CMAKE_BUILD_TYPE Debug)
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g -Wall -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64")
SET(CMAKE_C_FLAGS_RELEASE "-O2 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64")
SET(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -Wall -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64")
SET(CMAKE_CXX_FLAGS_RELEASE "-O2 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64" )

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR})

FIND_PACKAGE(Threads)

################################################################################
# CLIENT                                                                       #
################################################################################

FILE(GLOB_RECURSE CLIENT_SRCS src/client/*.c)
ADD_EXECUTABLE(dnbd3-client ${CLIENT_SRCS})



################################################################################
# SERVER                                                                       #
################################################################################

FILE(GLOB_RECURSE SERVER_SRCS src/server/*.c)
ADD_EXECUTABLE(dnbd3-server ${SERVER_SRCS})
TARGET_LINK_LIBRARIES(dnbd3-server ${CMAKE_THREAD_LIBS_INIT})


################################################################################
# MODULE                                                                       #
################################################################################

SET(MODULE_NAME dnbd3)
SET(MODULE_FILE ${MODULE_NAME}.ko)
FILE(GLOB MODULE_SOURCE_FILES src/kernel/*.c)
FILE(GLOB MODULE_HEADER_FILES src/kernel/*.h src/*.h)

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
