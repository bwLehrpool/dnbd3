cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-bench
        LANGUAGES C)

# add compile option to enable enhanced POSIX pthread features
add_definitions(-D_GNU_SOURCE)

set(DNBD3_BENCH_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/connection.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/helper.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/main.c)
set(DNBD3_BENCH_HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/connection.h
                             ${CMAKE_CURRENT_SOURCE_DIR}/helper.h)

add_executable(dnbd3-bench ${DNBD3_BENCH_SOURCE_FILES})
target_link_libraries(dnbd3-bench dnbd3-version dnbd3-shared ${CMAKE_THREAD_LIBS_INIT})
install(TARGETS dnbd3-bench RUNTIME DESTINATION bin
        COMPONENT bench)

add_linter(dnbd3-bench-lint "${DNBD3_BENCH_SOURCE_FILES}" "${DNBD3_BENCH_HEADER_FILES}")
add_linter_fix(dnbd3-bench-lint-fix "${DNBD3_BENCH_SOURCE_FILES}" "${DNBD3_BENCH_HEADER_FILES}")
