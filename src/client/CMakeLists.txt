cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-client
        LANGUAGES C)

# add compile option to enable enhanced BSD netdb features
add_definitions(-D_GNU_SOURCE)

set(DNBD3_CLIENT_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/client.c)

add_executable(dnbd3-client ${DNBD3_CLIENT_SOURCE_FILES})
target_link_libraries(dnbd3-client dnbd3-version dnbd3-build dnbd3-shared)
install(TARGETS dnbd3-client RUNTIME DESTINATION bin
        COMPONENT kernel)

add_linter(dnbd3-client-lint "${DNBD3_CLIENT_SOURCE_FILES}")
add_linter_fix(dnbd3-client-lint-fix "${DNBD3_CLIENT_SOURCE_FILES}")
