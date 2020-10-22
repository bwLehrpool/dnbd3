cmake_minimum_required(VERSION 3.10)

# set the project name
project(dnbd3-systemd)

# define all systemd related files
set(DNBD3_SYSTEMD_FILES ${CMAKE_CURRENT_SOURCE_DIR}/dnbd3-server.service)

# install systemd service files
install(FILES ${DNBD3_SYSTEMD_FILES}
        DESTINATION /usr/lib/systemd/system
        COMPONENT server)
