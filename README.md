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

Chameleon uses CMake to build the executable and supports Debug and Release builds.  For the following we'll install using the Debug build which is slower at runtime but performs sanity checks and is capable of printing significant amounts of information to help developers debug.  The build process for Release builds is almost identical; just substitute `Release` in place of `Debug` below.

**Note:** For the debug build, you should install `libcompel` by passing `-d / --debug` to `install-compel.sh` above

* Configure the build:

```
$ cd ~/popcorn-chameleon
$ mkdir build && cd build
$ cmake -DCMAKE_BUILD_TYPE=Debug -DCOMPEL_INSTALL_DIR=/usr/local/chameleon -DDYNAMORIO_INSTALL_DIR=/usr/local/chameleon -DPOPCORN_INSTALL_DIR=/usr/local/chameleon ..
$ make -j$(nproc)
```

* If the configure/build succeeds, the Chameleon executable is placed in `build/bin/chameleon`

# Building applications for Chameleon

Chameleon requires metadata generated by Popcorn Linux's compiler; you'll need to build applications using the installed compiler.  As part of installing the compiler, both clang/LLVM and musl-libc should have been installed.  musl-libc (an easier to use and cleaner libc alternative to glibc) installs a driver script which can be used as a drop-in replacement for `gcc` or `clang`.  The driver script under the hood swaps out system headers and libraries for those installed with the Popcorn Linux compiler.  In addition, you'll need to add several flags to help generate code compatible with Chameleon and its current limitations.  For example to compile a source code file `foo.c` using the driver:

```
$ /usr/local/chameleon/x86_64/bin/musl-clang -static \
    -popcorn-metadata -popcorn-target=x86_64-linux-gnu -secure-popcorn \
    -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -mno-red-zone \
    -c foo.c
```

The extra arguments do the following:

* `-popcorn-metadata`: add instrumentation in the compiler to generate stack transformation metadata
* `-popcorn-target=x86_64-linux-gnu`: by default Popcorn Linux's compiler generates object files for multiple architectures; this flag instructs it to only generate object files for x86-64
* `-secure-popcorn`: tailor metadata output for Chameleon
* `-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer`: force the compiler to use a frame pointer to both avoid limitations in metadata generation and to generate cleaner code for Chameleon
* `-mno-red-zone`: don't use the [red zone](https://en.wikipedia.org/wiki/Red_zone_%28computing%29) due to limitations in Chameleon

After generating a target application executable, you'll need to run a post-processing tool to prepare the metadata contained in the binary for runtime stack transformation.  For an executable named `foo`:

```
$ /usr/local/chameleon/bin/gen-stackinfo -f foo
```

# Running applications under Chameleon

Chameleon traces the targeted application using Linux's `ptrace` interface.  Thus, Chameleon acts as a "shell" around the application - users launch chameleon and specify the command line arguments for the target application.  Chameleon will `fork()` and `exec()` the application, forwarding the command line arguments.  For example, to run an application `foo` with arguments `arg1 arg2` under Chameleon:

```
$ cd ./popcorn-chameleon/build
$ ./bin/chameleon -- foo arg1 arg2
```

The double dash `--` separates arguments to chameleon (all arguments before the dashes) from how Chameleon will launch the target application (all arguments after the dashes).  Run Chameleon with `-h` to see all supported command line options

### No randomization

To run an application with no runtime code randomization:

```
$ ./bin/chameleon -n -- foo arg1 arg2
```

This is useful when sanity-checking that either Chameleon or the application works without any modification.

### Initial randomization

To run an application with an initial randomization:

```
$ ./bin/chameleon -- foo arg1 arg2
```

In this configuration, Chameleon forks the target application and performs an initial randomization of the code section before starting the application.  The initial randomization is the only modification made to the target; Chameleon will not perform any re-randomization.

### Continuous code re-randomization

To run an application under continous code re-randomization:

```
$ ./bin/chameleon -p 1000 -- foo arg1 arg2
```

In this configuration, Chameleon will interrupt the target application every specified period (in milliseconds) and swap in newly randomized code.  Chameleon runs a background thread while waiting for the next interrupt which generates a new set of randomized code.  At the interrupt, Chameleon drops the application's code pages (forcing it to load in the newly randomized code on demand) and transforms the application threads' stacks to match the newly randomized code.  All of this process is completely transparent to the target application.

### Other useful options

* `-d`: print verbose debugging information to stderr - you'll probably want to redirect stderr to a file (only available in Debug builds)

* `-t`: trace the execution path of the child by single-stepping and writing each executed instruction's address to the specified trace file (only available in Debug builds) - **Warning**: extremely slow!

* `-r`: when used in conjuction with `-t`, print the register set used for each instruction to the trace log - **Warning**: even slower and can cause gigantic trace logs!

