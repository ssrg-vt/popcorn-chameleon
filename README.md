# Secure Popcorn Linux / Chameleon runtime monitoring & state transformation framework

TODO description

# Installation

## Prerequisites

Before installing Chameleon, we need to install several pieces of open source software.  For the following directions we'll refer to the *installation directory* as the directory where supporting software is installed (and the final built Chameleon executable should you choose to install it).  The directions default to using `/usr/local/chameleon` as the installation directory.  Additionally, we'll refer to *Chameleon's repository*, which is the location where you've cloned `popcorn-chameleon`.  The directions default to `~/popcorn-chameleon` as the repository's location.

**Tip:** if you use `/usr/local/chameleon` as the installation directory, change the ownership permissions so you don't have to be root to install software.

### DynamoRIO

[DynamoRIO](http://dynamorio.org/) is a dynamic binary instrumentation platform.  While Chameleon doesn't use DynamoRIO's instrumentation tools, it does use DynamoRIO as a standalone disassembler/re-assembler.  Install DynamoRIO by doing the following:

* Download the precompiled DynamoRIO release tarball from the [downloads](https://github.com/DynamoRIO/dynamorio/wiki/Downloads) page (choose the vanilla Linux release).  Chameleon has been tested with release 7.0.0; your mileage may vary with other releases.

* Untar the tarball - this should create a directory (e.g., `DynamoRIO-Linux-7.0.0-RC1`) in which resides all of the precompiled libraries and headers.  Move all the contents of this directory into the installation directory:

```
$ ls /usr/local/chameleon
ACKNOWLEDGEMENTS  bin32  bin64  cmake  docs  drmemory  dynamorio  ext  include  lib32  lib64  License.txt  logs  README  samples  tools
```

### libcompel

libcompel is a library that facilitates creating and injecting code called *parasites* into applications controlled by ptrace.  libcompel is released as part of [CRIU](https://criu.org/Main_Page); we don't use any other part of CRIU, however.  Install libcompel by doing the following:

* We need to patch libcompel to both fix some bugs and add extra functionality, so unfortunately we can't simply use a release tarball.  Clone CRIU from the [GitHub repository](https://github.com/checkpoint-restore/criu).  Then, use the `install-compel.sh` script from Chameleon's repository in `util` to install the library.  For example:

```
$ git clone https://github.com/checkpoint-restore/criu.git
$ ls ~/
criu  popcorn-chameleon
$ cd ~/popcorn-chameleon/util
$ ./install-compel.sh -c ~/criu -i /usr/local/chameleon   # run with -h for more options
```

**Tip:** The script allows building libcompel in optimized and debug formats (using the `-d / --debug` flag to enable debugging).  Building Chameleon in either Release or Debug selects the appropriate version of the library.  It helps to have both installed so that you can easily switch between Release and Debug builds of Chameleon; you may want to run the libcompel installation script twice to get both versions.

### Popcorn Linux

[Popcorn Linux](http://popcornlinux.org/) is an operating system, compiler and runtime for executing and migrating natively compiled C/C++ applications between heterogeneous-ISA CPUs (e.g., ARM64, x86-64).  Popcorn Linux's compiler generates metadata describing the stack layout of functions at *equivalence points*, allowing a state transformation runtime to rewrite the stack to a new format when migrating between heterogeneous-ISA CPUs.  Chameleon leverages & extends Popcorn Linux's compiler and runtime to enable runtime re-randomization of an application's stack.  Install Popcorn Linux by doing the following:

* Clone Popcorn Linux's compiler from the [GitHub repository](https://github.com/ssrg-vt/popcorn-compiler) and switch to the `security` branch:

```
$ git clone https://://github.com/ssrg-vt/popcorn-compiler.git
$ ls ~/
criu  popcorn-chameleon  popcorn-compiler
$ cd ~/popcorn-compiler
$ git checkout security
```

* Install the compiler using the `install_compiler.py` script.  This may take a while; the script downloads and builds clang/LLVM, binutils and a host of libraries and other utilities.

```
$ ./install_compiler.py --install-path /usr/local/chameleon --install-all --chameleon
```

## Building Chameleon

Chameleon uses CMake to build the executable and supports Debug and Release builds.  For the following we'll install using the Debug build which is slower at runtime but performs sanity checks and is capable of printing significant amounts of information to help developers Debug.  The build process for Release builds is almost identical; just substitute `Release` in place of `Debug` below.

**Note:** For the debug build, you should install `libcompel` by passing `-d / --debug` to `install-compel.sh` above

* Configure the build:

```
$ cd ~/popcorn-chameleon
$ mkdir build && cd build
$ cmake -DCMAKE_BUILD_TYPE=Debug -DCOMPEL_INSTALL_DIR=/usr/local/chameleon -DDYNAMORIO_INSTALL=/usr/local/chameleon -DPOPCORN_INSTALL_DIR=/usr/local/chameleon ..
$ make -j$(nproc)
```

* If the configure/build succeeds, the Chameleon executable is placed in `build/bin/chameleon`

# Running applications under Chameleon

TODO description

