cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-fuse
        LANGUAGES C)

find_package(Fuse REQUIRED)

# add compile option to enable enhanced POSIX pthread features
add_definitions(-D_GNU_SOURCE)

add_executable(dnbd3-fuse ${CMAKE_CURRENT_SOURCE_DIR}/connection.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/helper.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/main.c)
target_include_directories(dnbd3-fuse PRIVATE ${FUSE_INCLUDE_DIRS})
target_link_libraries(dnbd3-fuse dnbd3-version dnbd3-shared ${FUSE_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
install(TARGETS dnbd3-fuse RUNTIME DESTINATION bin
        COMPONENT fuse)
