# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# Use pkg-config to get the directories and then use these values
# in the FIND_PATH() and FIND_LIBRARY() calls
find_package(PkgConfig QUIET)
pkg_check_modules(PKG_Libatomic QUIET libatomic)

set(Libatomic_COMPILE_OPTIONS ${PKG_Libatomic_CFLAGS_OTHER})
set(Libatomic_VERSION ${PKG_Libatomic_VERSION})

find_path(Libatomic_INCLUDE_DIR
          NAMES stdatomic.h
          HINTS ${PKG_Libatomic_INCLUDE_DIRS})
find_library(Libatomic_LIBRARY
             NAMES atomic
             HINTS ${PKG_Libatomic_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libatomic
                                  FOUND_VAR Libatomic_FOUND
                                  REQUIRED_VARS Libatomic_LIBRARY
                                  VERSION_VAR Libatomic_VERSION
                                  FAIL_MESSAGE "Library 'atomic' is not available! Please install this required library!")

if(Libatomic_FOUND AND NOT TARGET Libatomic::Libatomic)
    add_library(Libatomic::Libatomic UNKNOWN IMPORTED)
    set_target_properties(Libatomic::Libatomic PROPERTIES
                          IMPORTED_LOCATION "${Libatomic_LIBRARY}"
                          INTERFACE_COMPILE_OPTIONS "${Libatomic_COMPILE_OPTIONS}"
                          INTERFACE_INCLUDE_DIRECTORIES "${Libatomic_INCLUDE_DIR}")
endif(Libatomic_FOUND AND NOT TARGET Libatomic::Libatomic)

mark_as_advanced(Libatomic_LIBRARY Libatomic_INCLUDE_DIR)

if(Libatomic_FOUND)
    set(Libatomic_LIBRARIES ${Libatomic_LIBRARY})
    set(Libatomic_INCLUDE_DIRS ${Libatomic_INCLUDE_DIR})
endif(Libatomic_FOUND)

# print found information
if(${CMAKE_VERSION} VERSION_GREATER "3.15.0")
    message(VERBOSE "Libatomic_FOUND: ${Libatomic_FOUND}")
    message(VERBOSE "Libatomic_VERSION: ${Libatomic_VERSION}")
    message(VERBOSE "Libatomic_INCLUDE_DIRS: ${Libatomic_INCLUDE_DIRS}")
    message(VERBOSE "Libatomic_COMPILE_OPTIONS: ${Libatomic_COMPILE_OPTIONS}")
    message(VERBOSE "Libatomic_LIBRARIES: ${Libatomic_LIBRARIES}")
endif(${CMAKE_VERSION} VERSION_GREATER "3.15.0")
