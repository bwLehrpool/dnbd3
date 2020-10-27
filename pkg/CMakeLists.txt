cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-pkg
        LANGUAGES C)

add_subdirectory(config)
add_subdirectory(systemd)
