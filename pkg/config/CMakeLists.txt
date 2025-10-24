cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-config
        LANGUAGES C)

# define all configuration files
set(DNBD3_CONFIG_FILES ${CMAKE_CURRENT_SOURCE_DIR}/alt-servers
                     ${CMAKE_CURRENT_SOURCE_DIR}/rpc.acl
                     ${CMAKE_CURRENT_SOURCE_DIR}/server.conf)

# install configuration files into sample directory
install(FILES ${DNBD3_CONFIG_FILES}
        DESTINATION /etc/dnbd3-server/sample
        COMPONENT server)
