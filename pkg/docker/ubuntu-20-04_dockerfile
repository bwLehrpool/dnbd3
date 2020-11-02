# use Ubuntu 20.04 as base image
FROM ubuntu:focal

# declare arguments that should be set by 'docker build --build-arg ...'
ARG DNBD3_PACKAGE_FILE_NAME

# copy built package file from host to docker image
COPY ${DNBD3_PACKAGE_FILE_NAME} /tmp

# install required dependencies
RUN apt-get update
RUN apt-get install -y libfuse2 libjansson4

# install installation package
RUN dpkg -i /tmp/${DNBD3_PACKAGE_FILE_NAME}

# use default config for dnbd3-server
RUN ln -s /etc/dnbd3-server/sample/server.conf /etc/dnbd3-server
RUN ln -s /etc/dnbd3-server/sample/alt-servers /etc/dnbd3-server

# make default storage point for dnbd3-server
RUN mkdir -p /mnt/storage

# expose the port of the dnbd3-server to the host
EXPOSE 5003

# run dnbd3-server
CMD [ "dnbd3-server", "-n" ]
