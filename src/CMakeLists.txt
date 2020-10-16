cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-src)

add_subdirectory(bench)
add_subdirectory(client)
add_subdirectory(fuse)
if(DNBD3_KERNEL_MODULE)
    add_subdirectory(kernel)
endif(DNBD3_KERNEL_MODULE)
add_subdirectory(server)
add_subdirectory(shared)
