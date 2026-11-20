cmake_minimum_required(VERSION 3.10)

include(FindPackageHandleStandardArgs)

find_package(PkgConfig QUIET)

if(PkgConfig_FOUND)
    pkg_check_modules(FUSE3 QUIET IMPORTED_TARGET fuse3)
endif()

if(FUSE3_FOUND)
    set(FUSE_INCLUDE_DIRS ${FUSE3_INCLUDE_DIRS})
    set(FUSE_LIBRARIES ${FUSE3_LINK_LIBRARIES})
    set(FUSE_VERSION ${FUSE3_VERSION})

    if(NOT TARGET FUSE::FUSE)
        add_library(FUSE::FUSE INTERFACE IMPORTED)
        set_target_properties(FUSE::FUSE PROPERTIES
            INTERFACE_LINK_LIBRARIES PkgConfig::FUSE3
        )
    endif()

else()
    # Fallback when pkg-config is unavailable.

    find_path(FUSE_INCLUDE_DIR
        NAMES fuse.h
        PATH_SUFFIXES fuse3
    )

    find_library(FUSE_LIBRARY
        NAMES fuse3
    )

    set(FUSE_INCLUDE_DIRS ${FUSE_INCLUDE_DIR})
    set(FUSE_LIBRARIES ${FUSE_LIBRARY})

    # Extract version from fuse_common.h.
    if(FUSE_INCLUDE_DIR AND
       EXISTS "${FUSE_INCLUDE_DIR}/fuse_common.h")

        file(STRINGS
            "${FUSE_INCLUDE_DIR}/fuse_common.h"
            FUSE_VERSION_LINES
            REGEX "^#define[ \t]+FUSE_(MAJOR|MINOR)_VERSION[ \t]+[0-9]+"
        )

        foreach(line IN LISTS FUSE_VERSION_LINES)
            if(line MATCHES "FUSE_MAJOR_VERSION[ \t]+([0-9]+)")
                set(FUSE_MAJOR_VERSION "${CMAKE_MATCH_1}")
            elseif(line MATCHES "FUSE_MINOR_VERSION[ \t]+([0-9]+)")
                set(FUSE_MINOR_VERSION "${CMAKE_MATCH_1}")
            endif()
        endforeach()

        if(DEFINED FUSE_MAJOR_VERSION AND
           DEFINED FUSE_MINOR_VERSION)
            set(FUSE_VERSION
                "${FUSE_MAJOR_VERSION}.${FUSE_MINOR_VERSION}")
        endif()
    endif()

    if(FUSE_INCLUDE_DIR AND FUSE_LIBRARY AND
       NOT TARGET FUSE::FUSE)

        add_library(FUSE::FUSE UNKNOWN IMPORTED)
        set_target_properties(FUSE::FUSE PROPERTIES
            IMPORTED_LOCATION "${FUSE_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${FUSE_INCLUDE_DIR}"
        )
    endif()
endif()

find_package_handle_standard_args(Fuse
    REQUIRED_VARS FUSE_INCLUDE_DIRS FUSE_LIBRARIES
    VERSION_VAR FUSE_VERSION
)

# Compatibility with projects using uppercase variables.
set(FUSE_FOUND ${Fuse_FOUND})

mark_as_advanced(
    FUSE_INCLUDE_DIR
    FUSE_LIBRARY
)