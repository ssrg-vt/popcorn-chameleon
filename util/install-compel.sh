#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
COMPEL_PATCH=$(readlink -f $DIR/../patches/compel.patch)
INSTALL=/usr/local/chameleon
LIBS=$INSTALL/lib64/release
ARGS="-j$(nproc)"
PATCH=1
DEBUG=0

function print_help {
  echo "Configure & install CRIU's libcompel for Chameleon"
  echo
  echo "Options:"
  echo "  -h | --help        : print help & exit"
  echo "  -c | --criu DIR    : CRIU source directory"
  echo "  -i | --install DIR : set installation directory"
  echo "  -n | --no-patch    : don't apply Chameleon's patch to compel sources"
  echo "  -d | --debug       : build debug version of libcompel"
  echo
  echo "See https://criu.org/Main_Page for more information on CRIU"
}

function die {
  echo "ERROR: $1"
  exit 1
}

while [[ $1 != "" ]]; do
  case $1 in
    -h | --help) print_help; exit 0;;
    -c | --criu) CRIU=$(readlink -f $2); shift;;
    -i | --install) INSTALL=$(readlink -f $2); shift;;
    -n | --no-patch) PATCH=0;;
    -d | --debug)
      DEBUG=1
      ARGS="$ARGS DEBUG=1"
      LIBS=$INSTALL/lib64/debug;;
  esac
  shift
done

if [[ -z "$CRIU" ]]; then
  print_help
  echo
  die "CRIU source directory not set";
fi
cd $CRIU || die "directory '$CRIU' does not exist"
if [[ ! -f "Makefile.compel" ]] || [[ ! -d "compel" ]]; then
  die "'$CRIU' is not a valid CRIU source directory"
fi

echo -e "Installing from source directory:\n  $(readlink -f $CRIU)\n" \
        "to installation directory:\n  $(readlink -f $INSTALL)"
if [[ $DEBUG -eq 1 ]]; then echo " -> DEBUG build <-"; fi
echo

if [[ $PATCH -eq 1 ]]; then
  if [[ ! -f "$COMPEL_PATCH" ]]; then die "could not find compel patch"; fi
  patch -p1 < $COMPEL_PATCH || die "could not patch compel"
fi

make mrproper || die "could not build compel"
make $ARGS PREFIX=$INSTALL LIBDIR=$LIBS install-compel \
  || die "could not install compel"

# It seems like CRIU's build system isn't including all headers during the
# install process; fix that here.
EXTRA_HEADERS="common/bitsperlong.h common/asm/bitsperlong.h common/scm.h"
for f in $EXTRA_HEADERS; do
  echo "Copying $f from $CRIU/include to $INSTALL/include/compel"
  cp $CRIU/include/$f $INSTALL/include/compel/$f
done

