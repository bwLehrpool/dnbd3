cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-bench)

# add compile option to enable enhanced POSIX pthread features
add_definitions(-D_GNU_SOURCE)

add_executable(dnbd3-bench ${CMAKE_CURRENT_SOURCE_DIR}/connection.c
                           ${CMAKE_CURRENT_SOURCE_DIR}/helper.c
                           ${CMAKE_CURRENT_SOURCE_DIR}/main.c)
target_link_libraries(dnbd3-bench dnbd3-version dnbd3-shared ${CMAKE_THREAD_LIBS_INIT})
install(TARGETS dnbd3-bench RUNTIME DESTINATION bin
        COMPONENT bench)
