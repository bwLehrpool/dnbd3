# - Find fuse
# Find the native fuse includes and library
#
#  FUSE_INCLUDE_DIR - where to find fuse/fuse.h.
#  FUSE_LIBRARIES   - List of libraries when using fuse.
#  FUSE_FOUND       - True if fuse found.


IF (FUSE_INCLUDE_DIR)
  # Already in cache, be silent
  SET(FUSE_FIND_QUIETLY TRUE)
ENDIF (FUSE_INCLUDE_DIR)

FIND_PATH(FUSE_INCLUDE_DIR fuse/fuse.h)

SET(FUSE_NAMES fuse)
FIND_LIBRARY(FUSE_LIBRARY NAMES ${FUSE_NAMES} )

# handle the QUIETLY and REQUIRED arguments and set FUSE_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(FUSE REQUIRED FUSE_LIBRARY FUSE_INCLUDE_DIR)

IF(FUSE_FOUND)
  SET( FUSE_LIBRARIES ${FUSE_LIBRARY} )
ELSE(FUSE_FOUND)
  SET( FUSE_LIBRARIES )
ENDIF(FUSE_FOUND)

MARK_AS_ADVANCED( FUSE_LIBRARY FUSE_INCLUDE_DIR )
