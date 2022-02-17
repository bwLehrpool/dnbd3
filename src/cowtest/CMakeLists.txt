cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-fuse-cow-test
        LANGUAGES C)


# find atomic library required by DNBD3_CLIENT_FUSE_COW_TEST
#find_package(Stdatomic REQUIRED)
#find_package(Libatomic REQUIRED)

# add compile option to enable enhanced POSIX pthread features
add_definitions(-D_GNU_SOURCE)

set(DNBD3_CLIENT_FUSE_COW_TEST_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/main.c)
#set(DNBD3_CLIENT_FUSE_COW_TEST_HEADER_FILES )


add_executable(dnbd3-fuse-cow-test ${DNBD3_CLIENT_FUSE_COW_TEST_SOURCE_FILES})
target_link_libraries(dnbd3-fuse-cow-test dnbd3-version dnbd3-shared ${CMAKE_THREAD_LIBS_INIT})


install(TARGETS dnbd3-fuse-cow-test RUNTIME DESTINATION bin
        COMPONENT cowtest)

#add_linter(dnbd3-fuse-lint "${DNBD3_CLIENT_FUSE_COW_TEST_SOURCE_FILES}" "${DNBD3_CLIENT_FUSE_COW_TEST_HEADER_FILES}")
#add_linter_fix(dnbd3-fuse-lint-fix "${DNBD3_CLIENT_FUSE_COW_TEST_SOURCE_FILES}" "${DNBD3_CLIENT_FUSE_COW_TEST_HEADER_FILES}")
