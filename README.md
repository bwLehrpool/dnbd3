# dnbd3 - distributed network block device (version 3)

The distributed network block device version 3 (dnbd3) is a network protocol similar to [nbd](https://github.com/NetworkBlockDevice/nbd) to implement a distributed block-based read-only storage system. Such a distributed block-based storage system consists of dnbd3 components, namly one or more servers and several clients. Servers are meant to expose virtual disk images as block devices to clients using dnbd3. Clients read data blocks from servers and implement failover and a load balancing mechanism to connect to the fastest server available for data exchange.

This repository contains the source code for the following dnbd3 components:

  - **dnbd3**: Linux kernel module client for dnbd3
  - **dnbd3-bench**: Benchmark utility to test dnbd3
  - **dnbd3-fuse**: Fuse client for dnbd3
  - **dnbd3-server**: Server to serve virtual disk images for dnbd3

The dnbd3 components have been built/tested on the following Linux kernel versions and Unix distributions:

  - Generic/Vanilla Kernel **4.9** to **6.1**
  - Archlinux with **Linux kernel 5.15.x** or **6.1.x**
  - Raspberry Pi OS with **Linux kernel 5.4.x**
  - Ubuntu 20.04 with **Linux kernel 5.4.x**
  - Ubuntu 18.04 with **Linux kernel 4.19.x**
  - CentOS 8 with **Linux kernel 4.18.x**
  - CentOS 7 with **Linux kernel 3.10.x**
  - AlmaLinux 8 with **Linux kernel 4.18.x**
  - Rocky Linux 8 with **Linux kernel 4.18.x**
  - FreeBSD 12.x and 13.x (only user space programs, eg. dnbd3-server)


## Build

### Preliminaries
A build of the dnbd3 components requires the installation of the following build tools and libraries under your supported Unix distribution.

#### Archlinux with Linux kernel 5.15.x or 5.10.x
```shell
pacman -S git \
          make \
          cmake \
          gcc \
          clang \
          linux-headers \  # or linux-lts-headers
          fuse2 \
          jansson \
          afl \
          dpkg \
          rpm-tools
```

#### Raspberry Pi OS with Linux kernel 5.4.x
```shell
apt-get install git \
                make \
                cmake \
                gcc \
                clang-format \
                raspberrypi-kernel-headers \
                libfuse-dev \
                libjansson-dev \
                afl \
                rpm
```

#### Ubuntu 20.04 with Linux kernel 5.4.x
```shell
apt-get install git \
                make \
                cmake \
                gcc \
                clang-format \
                linux-headers-generic \
                libfuse-dev \
                libjansson-dev \
                rpm
```

Note that `afl` is not available on Ubuntu 20.04 and should be built from the [original sources](https://github.com/google/AFL).

#### Ubuntu 18.04 with Linux kernel 4.19.x
```shell
apt-get install git \
                make \
                cmake \
                gcc \
                clang-format \
                linux-headers-generic \
                libfuse-dev \
                libjansson-dev \
                afl \
                rpm
```

#### {CentOS, AlmaLinux, Rocky Linux} 8 with Linux kernel 4.18.x
```shell
yum install git \
            make \
            cmake \
            gcc \
            clang-tools-extra \
            kernel-devel \
            elfutils-libelf-devel \
            fuse-devel \
            jansson-devel \
            libatomic \
            rpm-build
```

Note that `afl` is not available on CentOS 8 and the likes and should be built from the [original sources](https://github.com/google/AFL).

#### CentOS 7 with Linux kernel 3.10.x
Before any required preliminaries can be installed, enable the `epel` package repository with the following command line calls:

```shell
yum install epel-release
yum repolist # refresh epel package repository
```

The `epel` package repository enables the installation of `cmake3` on CentOS 7 which is later required to build dnbd3 components.
Then, install the required preliminaries with the following command line call as usual:

```shell
yum install git \
            make \
            cmake3 \
            gcc \
            kernel-devel \
            elfutils-libelf-devel \
            rpm-build
```

Note that `afl` is not available on CentOS 7 and should be built from the [original sources](https://github.com/google/AFL).

> **Warning: All dnbd3 components can only be built if a GCC compiler with stdatomic support is used.
> This feature is available with GCC 4.9 or later as part of the C11 language support.
> Since CentOS 7 is shipped with GCC 4.8 you have to install a new GCC version greater or equal than GCC 4.9.**

The installation of GCC 7.3 on CentOS requires some additional instructions as follows.
First, install Software Collections on your system that allows you to build, install, and use multiple versions of GCC on the same system withoutaffecting system-wide installed packages. Software collections is part of the CentOS `extras` repository and can be installed by running the following command:

```shell
yum install centos-release-scl
```

After installation of Software Collections, install the Developer Toolset in version 7 and additional packages with the following command line call:

```shell
yum install devtoolset-7 \
            devtoolset-7-libatomic-devel \
            llvm-toolset-7-git-clang-format \
            fuse-devel \
            jansson-devel
```

To access GCC 7.3, you need to launch a new shell instance using the Software Collections `scl` tool:

```shell
scl enable devtoolset-7 llvm-toolset-7 bash
```

Now, GCC 7.3 is the default version in your current shell.
This allows you to build all dnbd3 components on CentOS 7.


#### FreeBSD 12.x and 13.x
```shell
pkg install git \
            cmake \
            gcc \
            clang-devel \
            pkgconf \
            fusefs-libs \
            jansson \
            afl \
            rpm4
```


### Preparation
Before a build takes place, you should create a `build` directory inside the root folder of the repository. After that, change your working directory to that new directory as follows:

```shell
mkdir build
cd build
```


### Configuration
A build of the dnbd3 components can be configured and customized by the following configuration variables (CMake cache entries):

| Variable                     | Type   | Values                                  | Default value                         | Description                                                          |
|:-----------------------------|:-------|:----------------------------------------|:--------------------------------------|----------------------------------------------------------------------|
| `CMAKE_BUILD_TYPE`           | STRING | {`Debug`, `Release`}                    | `Debug`                               | Build configuration of the dnbd3 project.                            |
| `KERNEL_BUILD_DIR`           | PATH   | {`a` .. `z`, `A` .. `Z`, `/`, `_`, `-`} | /lib/modules/`uname -r`/build         | Path to Linux kernel modules to compile against.                     |
| `KERNEL_INSTALL_DIR`         | PATH   | {`a` .. `z`, `A` .. `Z`, `/`, `_`, `-`} | /lib/modules/`uname -r`/extra         | Path to install Linux kernel modules.                                |
| `KERNEL_SCRIPTS_DIR`         | PATH   | {`a` .. `z`, `A` .. `Z`, `/`, `_`, `-`} | /lib/modules/`uname -r`/build/scripts | Path to Linux kernel scripts directory.                              |
| `DNBD3_KERNEL_MODULE`        | OPTION | {`ON`, `OFF`}                           | `ON`                                  | Build the dnbd3 Linux kernel module.                                 |
| `DNBD3_BENCHMARK`            | OPTION | {`ON`, `OFF`}                           | `OFF`                                 | Enable build of dnbd3-bench.                                         |
| `DNBD3_CLIENT_FUSE`          | OPTION | {`ON`, `OFF`}                           | `ON`                                  | Enable build of dnbd3-fuse.                                          |
| `DNBD3_SERVER`               | OPTION | {`ON`, `OFF`}                           | `ON`                                  | Enable build of dnbd3-server.                                        |
| `DNBD3_SERVER_FUSE`          | OPTION | {`ON`, `OFF`}                           | `OFF`                                 | Enable FUSE-Integration for dnbd3-server.                            |
| `DNBD3_SERVER_AFL`           | OPTION | {`ON`, `OFF`}                           | `OFF`                                 | Build dnbd3-server for usage with afl-fuzz.                          |
| `DNBD3_SERVER_DEBUG_LOCKS`   | OPTION | {`ON`, `OFF`}                           | `OFF`                                 | Add lock debugging code to dnbd3-server.                             |
| `DNBD3_SERVER_DEBUG_THREADS` | OPTION | {`ON`, `OFF`}                           | `OFF`                                 | Add thread debugging code to dnbd3-server.                           |
| `DNBD3_RELEASE_HARDEN`       | OPTION | {`ON`, `OFF`}                           | `OFF`                                 | Compile dnbd3 programs in Release build with code hardening options. |
| `DNBD3_PACKAGE_DOCKER`       | OPTION | {`ON`, `OFF`}                           | `OFF`                                 | Enable packaging of Docker image.                                    |

A value from the range of appropriate values can be assigend to each configuration variable by executing CMake once with the following command pattern:

```shell
cmake -D<VARIABLE>=<VALUE> [-D ...] ../.
```

> **Note that the default compiler on FreeBSD 12.x and 13.x is clang/llvm and should be changed to gcc by appending the set CMake compiler configuration variable -DCMAKE_C_COMPILER=gcc to the CMake configuration command.**


### Cross-Compiling
With the help of CMake, it is also possible to cross-compile the dnbd3 components for a Linux target architecture other than the compiling Linux host architecture. This repository is shipped with two CMake toolchain files to cross-compile all components for the following two Linux target architectures if necessary.

> **Note that all used header files (eg. Linux kernel headers) and libraries (eg. jansson, fuse) for the target architecture are installed and set up properly, so that the cross-compiler can find and use them.**


#### Cross-Compiling for _powerpc_ Target
If you want to cross-compile all dnbd3 components for the _powerpc_ Linux target architecture (eg. for a Mac G5), make sure that the `powerpc-linux-gnu-gcc` cross-compiler is installed on your host system. Then, call CMake with the shipped toolchain file for this specific cross-compiler as follows.

```shell
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain/PowerpcLinuxGnu.cmake [-D ...] ../.
```


#### Cross-Compiling for _aarch64_ Target
If you want to cross-compile all dnbd3 components for the _aarch64_ Linux target architecture (eg. for a Raspberry Pi 4), make sure that the `aarch64-linux-gnu-gcc` cross-compiler is installed on your host system. Then, call CMake with the shipped toolchain file for this specific cross-compiler as follows.

```shell
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain/Aarch64LinuxGnu.cmake [-D ...] ../.
```


### Debug
In the `Debug` build configuration, all dnbd3 components can be built by calling `make`:

```shell
make
```

Optionally, the output files can be installed with superuser permissions on the local system using the Makefile target `install`:

```shell
sudo make install
sudo depmod -a  # only required if DNBD3_KERNEL_MODULE is enabled
```


### Packages
In the `Release` build configuration, installation packages can be built by calling the make target `package`:

```shell
make package
```

This target creates a Debian installation package (\*.deb), a RPM installation package (\*.rpm) and a compressed archive (\*.tar.gz) containing the built dnbd3 components.


### Sources
In the `Release` build configuration, sources can be built by calling the make target `source`:

```shell
make source
```

This target creates compressed archives (\*_source.tar.gz and \*_source.zip) containing the source code of this repository for code distribution purposes.


### Docker image
A docker image of the built dnbd3 components can be created in the `Release` build configuration with the option `DNBD3_PACKAGE_DOCKER=ON`, `DNBD3_SERVER=ON` and `DNBD3_KERNEL_MODULE=OFF`. The image is based on Ubuntu 20.04 and a created docker container from it starts the embedded dnbd3-server automatically.

Before the image is built, make sure that your docker daemon runs and you are a member of the `docker` group to access the docker deamon without any super user privileges. Then, build the docker image based on either Ubuntu 20.04 or Archlinux by calling one of the following Make target:

```
make docker-ubuntu-20-04
make docker-archlinux
```

The built docker image is saved as archive file (\*_ubuntu-20-04_docker.tar) and can be deployed to other machines. On each machine, the created image can be loaded with the following docker client call:

```shell
docker image load -i *_ubuntu-20-04_docker.tar
```

After the image is loaded, a docker network needs to be available so that each docker container based on this image can establish a network connection. Therefore, a docker network called `dnbd3` is created with the following docker client call:

```shell
docker network create --driver=bridge --subnet=192.168.100.0/24 dnbd3
```

If the network is present, docker containers with a name of form `dnbd3-server<NUMBER>` and an IPv4 address from the network's subnet can be created using docker client calls like the following ones:

```
docker container create --name dnbd3-server1 --ip 192.168.100.10  --network dnbd3 <IMAGE_TAG>
docker container create --name dnbd3-server2 --ip 192.168.100.50  --network dnbd3 <IMAGE_TAG>
docker container create --name dnbd3-server3 --ip 192.168.100.100 --network dnbd3 <IMAGE_TAG>
docker container create --name dnbd3-server4 --ip 192.168.100.123 --network dnbd3 <IMAGE_TAG>
```

Note that the image is already tagged with an `IMAGE_TAG` which is set to the current dnbd3 package version number and follows the format `dnbd3:<DNBD3_VERSION>`. The `IMAGE_TAG` can be reused to create a docker container. Finally, each container based on the image can be started with the following docker client call:

```
docker container start -a dnbd3-server<MUNBER>
```


## Configuration of _dnbd3-server_
The dnbd3-server is started according to the following command line call.

```shell
dnbd3-server -c <CONFIG_DIR>
```

An operation of the dnbd3-server requires a configuration directory to provide proper functionality. The configuration directory should contain two configuration files, namely the _alt-servers_ and the _server.conf_ file.


### Configuration file _alt-servers_
The _alt-servers_ configuration file specifies the list of known alt-servers for the dnbd3-server. The configuration in the file is specified the INI file format as shown in the following.

```ini
[Address]
comment=Whatever
for=purpose # where purpose is either "client" or "replication"
namespace=some/path/
```

All fields in an INI section are optional. If the `for` key is missing, the dnbd3-server will be used for replication and will be propagated to clients that request a list of alt servers. The `namespace` key can be specified multiple times per INI section. If this key is missing, the server will be used for all image names. Otherwise, it will only be used for images which's name starts with one of the given strings.

If the dnbd3-server is not running in proxy mode, this file won't do much.


### Configuration file _server.conf_
The _server.conf_ file is the main configuration file of the dnbd3-server. The configuration in the file is specified the INI file format as shown in the following.

```ini
[dnbd3]
basePath=/srv/openslx/dnbd3 # virtual root of image files
serverPenalty=1234 # artificial acceptance delay for incoming server connections (µs)
clientPenalty=2345 # artificial acceptance delay for incoming client connection (µs)
isProxy=true # enable proxy mode - will try to replicate from alt-servers if a client requests unknown image
uplinkTimeout=1250 # r/w timeout for connections to uplink servers
```


## Debugging
Debugging of the Linux kernel modules and the user space utility requires this project to be built in the `Debug` configuration.

### Linux kernel module
The Linux kernel module **dnbd3** supports the Linux kernel's dynamic debug feature if the Linux kernel is built with the enabled kernel configuration `CONFIG_DYNAMIC_DEBUG`. The dynamic debug feature allows the printing of customizable debug messages into the Linux kernel's message buffer.

Dynamic debug for the modules can be either enabled at module initialization or during operation. At module initialization, dynamic debug can be enabled by modprobe using the "fake" module parameter `dyndbg`:

```shell
modprobe dnbd3 dyndbg=+pflmt
```

The module parameter `dyndbg` customizes the debug messages written into the Linux kernel's message buffer. The specific value `+pflmt` enables all debug messages in the source code and includes function name (`f`), line number (`l`), module name (`m`) and thread ID (`t`) for each executed debug statement from the source code.

During operation, debug messages from debug statements in the code can be customized and enabled dynamically as well using the debugfs control file `<DEBUG_FS>/dynamic_debug/control` where `DEBUG_FS` is the mount point of a mounted DebugFS, eg. `/sys/kernel/debug`:

```shell
echo "module dnbd3 +pflmt" > <DEBUG_FS>/dynamic_debug/control
```

More information regarding the Linux kernel's dynamic debug feature can be found in the [Linux kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/dynamic-debug-howto.html).


## Development notes

### Code style of source code files
The code style fo all source code files can be checked by calling the make target `lint`:

```shell
make lint
```

If some source code files do not meet the project's code style, they can be fixed automatically by calling the make target `lint-fix`:

```shell
make lint-fix
```


### Resource locking in dnbd3
The order of aquiring multiple locks is very important, as you'll produce a possible deadlock if you do it in the wrong order. Take very good care of locking order if you have lots of functions that call each other. You might lose track of what's going on.


#### dnbd3-fuse
This is a list of used locks, in the order they have to be aquired if you must hold multiple locks.

```
mutexInit
newAltLock
altLock
connection.sendMutex
requests.lock
```


#### dnbd3-server
This is a list of used locks, in the order they have to be aquired if you must hold multiple locks. Take a look at the lock priority defines in _src/server/locks.h_ for the effective order.

```
reloadLock
loadLock
remoteCloneLock
_clients_lock
_clients[].lock
integrityQueueLock
imageListLock
_images[].lock
uplink.queueLock
altServersLock
client.sendMutex
uplink.rttLock
uplink.sendMutex
aclLock
initLock
dirLock
```

If you need to lock multiple clients or images or etc at once, lock the client with the lowest array index first.

If the program logic would require to aquire the locks in a different order, you have to rework the code. For example, if you hold the lock for client 10 and you need to look up some other client. You must not simply fetch the _clients_lock now and then iterate over the clients until you find the one you need, as it violates the above order to first lock on the clients array and then the clients lock. Instead, you need to release client 10's lock, then lock on _clients_lock and iterate over the clients. Now you check if you either encounter the client you originally held the lock on, or the client you are looking for. You immediately lock on those two. You can then release the _clients_lock and work with both clients.
This described implementation advice is visualized in the following pseudo C code.

```C
/* client10 is assumed to be a pointer to a client, which happens to be at index 10 */
lock (client10->lock);
/* ... */
/* we need another client */
unlock(client10->lock);

lock(_clients_lock);
client clientA = NULL, clientB = NULL;
for (i = 0; i < _num_clients; ++i) {
	if (client[i] == client10) {
		clientA = client[i];
		lock(clientA.lock);
	} else if (client[i].something == <whatever>) {
		clientB = client[i];
		lock(clientB.lock);
	}
}
unlock(_clients_lock);

if (clientA && clientB) {
    /* make sure we actually found both */
	/* do something important with both clients */
}

if (clientA)
    unlock(clientA.lock);
if (clientB)
    unlock(clientB.lock);
```
