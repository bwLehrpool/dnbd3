cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-client
        LANGUAGES C)

# suppress -Wmultichar warnings
add_compile_options(-Wno-multichar)

# add compile option to enable enhanced BSD netdb features
add_definitions(-D_GNU_SOURCE)

add_executable(dnbd3-client ${CMAKE_CURRENT_SOURCE_DIR}/client.c)
target_link_libraries(dnbd3-client dnbd3-version dnbd3-shared)
install(TARGETS dnbd3-client RUNTIME DESTINATION bin
        COMPONENT kernel)
