cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-fuse
        LANGUAGES C)

find_package(Fuse REQUIRED)

# find atomic library required by dnbd3-fuse
find_package(Stdatomic REQUIRED)
find_package(Libatomic REQUIRED)

# add compile option to enable enhanced POSIX pthread features
add_definitions(-D_GNU_SOURCE)

set(DNBD3_FUSE_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/connection.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/helper.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/main.c)
set(DNBD3_FUSE_HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/connection.h
                            ${CMAKE_CURRENT_SOURCE_DIR}/helper.h)

add_executable(dnbd3-fuse ${DNBD3_FUSE_SOURCE_FILES})
target_include_directories(dnbd3-fuse PRIVATE ${FUSE_INCLUDE_DIRS})
target_link_libraries(dnbd3-fuse dnbd3-build dnbd3-version dnbd3-shared ${FUSE_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
install(TARGETS dnbd3-fuse RUNTIME DESTINATION bin
        COMPONENT fuse)

add_linter(dnbd3-fuse-lint "${DNBD3_FUSE_SOURCE_FILES}" "${DNBD3_FUSE_HEADER_FILES}")
add_linter_fix(dnbd3-fuse-lint-fix "${DNBD3_FUSE_SOURCE_FILES}" "${DNBD3_FUSE_HEADER_FILES}")
