cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-src
        LANGUAGES C)

if(DNBD3_BENCHMARK)
    add_subdirectory(bench)
endif(DNBD3_BENCHMARK)

if(DNBD3_KERNEL_MODULE)
    add_subdirectory(client)
    add_subdirectory(kernel)
endif(DNBD3_KERNEL_MODULE)

if(DNBD3_CLIENT_FUSE)
    add_subdirectory(fuse)
endif(DNBD3_CLIENT_FUSE)

if(DNBD3_CLIENT_FUSE_COW_TEST)
    add_subdirectory(cowtest)
endif(DNBD3_CLIENT_FUSE_COW_TEST)

if(DNBD3_SERVER)
    add_subdirectory(server)
endif(DNBD3_SERVER)

add_subdirectory(shared)
