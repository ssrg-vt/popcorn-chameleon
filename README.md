# Secure Popcorn Linux / Chameleon runtime monitoring & state transformation framework

TODO description

# Installation

Chameleon uses CMake to build the executable.  First, however, Chameleon needs several pieces of open source software.  For the following directions we'll refer to the *installation directory* as the directory where supporting software is installed (and the final built Chameleon executable should you choose to install it).  The directions default to using `</usr/local/chameleon>` as the installation directory.  Additionally, we'll refer to *Chameleon's repository*, which is the location where you've cloned `<popcorn-chameleon>`.  The directions default to `<~/popcorn-chameleon>` as the repository's location.

**Tip:** if you use `</usr/local/chameleon>` as the installation directoyr, change the ownership permissions so you don't have to be root to install software.

### DynamoRIO

[DynamoRIO](http://dynamorio.org/) is a dynamic binary instrumentation platform.  While Chameleon doesn't use DynamoRIO's instrumentation tools, it does use DynamoRIO as a standalone disassembler/re-assembler.  Install DynamoRIO by doing the following:

* Download the precompiled DynamoRIO release tarball from the [downloads](https://github.com/DynamoRIO/dynamorio/wiki/Downloads) page (choose the Linux release).  Chameleon has been tested with release 7.0.0; your mileage may vary with other releases.

* Untar the tarball - this should create a directory (e.g., `<DynamoRIO-Linux-7.0.0-RC1>`).  Move all the contents of this directory into the installation directory:

```
$ ls /usr/local/chameleon
ACKNOWLEDGEMENTS  bin32  bin64  cmake  docs  drmemory  dynamorio  ext  include  lib32  lib64  License.txt  logs  README  samples  tools
```

### libcompel

libcompel is a library that facilitates creating and injecting code (called *parasites*) into applications controlled by ptrace.  libcompel is released as part of [CRIU](https://criu.org/Main_Page); we don't use any other part of CRIU, however.  Install libcompel by doing the following:

* We need to patch libcompel to both fix some bugs and add extra functionality, so unfortunately we can't simply use a release tarball.  Clone CRIU from the [GitHub repository](https://github.com/checkpoint-restore/criu).  Then, use the `<install-compel.sh>` script from Chameleon's repository in `<util>` to install the library.  For example:

```
$ git clone https://github.com/checkpoint-restore/criu.git
$ ls ~/
criu
$ cd ~/popcorn-chameleon/util
$ ./install-compel.sh -c ~/criu -i /usr/local/chameleon # run with -h for more options
```

**Tip:** The script allows building libcompel in optimized and debug formats (using the `<-d / --debug>` flag).  It helps to have both installed so that you can easily switch between Release and Debug builds of Chameleon; you may want to run the libcompel installation script twice to get both versions.

### Popcorn Linux

TODO

