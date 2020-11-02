# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# create a pseudo target to do packaging before docker image is built
add_custom_target(package_docker
                  COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target package
                  VERBATIM)

# macro to build a docker image based on a provided Dockerfile and an installation package
macro(add_docker_image TARGET_NAME DOCKER_IMAGE DOCKER_FILE DOCKER_TAG PACKAGE_FILE BUILD_DIR)
    get_filename_component(PACKAGE_FILE_PATH ${PACKAGE_FILE} PATH)
    get_filename_component(PACKAGE_FILE_NAME ${PACKAGE_FILE} NAME)

    # commands and target to build docker image
    add_custom_command(OUTPUT ${DOCKER_IMAGE}
                       COMMAND docker image build -t ${DOCKER_TAG} --file ${DOCKER_FILE} --build-arg DNBD3_PACKAGE_FILE_NAME=${PACKAGE_FILE_NAME} ${BUILD_DIR}
                       COMMAND docker image save -o ${DOCKER_IMAGE} ${DOCKER_TAG}
                       COMMAND docker image rm ${DOCKER_TAG}
                       DEPENDS ${DOCKER_FILE}
                               package_docker)
    add_custom_target(${TARGET_NAME}
                      DEPENDS ${DOCKER_IMAGE})    
endmacro(add_docker_image TARGET_NAME DOCKER_IMAGE DOCKER_FILE PACKAGE_FILE)
