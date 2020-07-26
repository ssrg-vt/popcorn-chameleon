#! /bin/bash

POPCORN=/usr/local/secure-popcorn

DO_GEN_STACKINFO=1

# Known corner case functions in musl-libc that should not be randomized
#  Uses locking intrinsic which hard-codes stack address w/o offset:
#    __expand_heap_node
#    __unlock
#    __unlockfile
#    popcorn_free
#    popcorn_get_arena
#    unlock_bin
#
#  General stack shenanians:
#    printf_core
BLACKLIST_MUSL="
  __expand_heap_node
  __floatscan
  __unlock
  __unlockfile
  popcorn_free
  popcorn_get_arena
  printf_core
  unlock_bin"
EXTRA_BLACKLIST=""
IDENTITY=""

function die {
  echo "Error: $1"
  exit 1
}

function print_help {
  echo "Arguments:"
  echo "  -f : Executable file name to prepare (required)"
  echo "  -n : Don't run gen-stackinfo (default = run gen-stackinfo)"
  echo "  -b \"func1 ...\" : extra functions to blacklist separated by a space"
  echo "  -i \"func1 ...\" : functions for which to do an identity randomization"
}

while [[ $1 != "" ]]; do
  case $1 in
    -f) EXEC=$2; shift;;
    -n) DO_GEN_STACKINFO=0;;
    -b) EXTRA_BLACKLIST="$2"; shift;;
    -i) IDENTITY="$2"; shift;;
    *) print_help; die "Unknown argument '$1'";;
  esac
  shift
done

# Check to make sure the user supplied a valid file
if [[ ! -f $EXEC ]]; then die "file $EXEC doesn't exist"; fi
if [[ "$(file $EXEC | grep 'ELF.*executable')" == "" ]]; then
  die "$EXEC is not a valid ELF executable"
fi

if [[ $DO_GEN_STACKINFO -eq 1 ]]; then
  $POPCORN/bin/gen-stackinfo -f $EXEC || die "could not generate stack info"
fi

# Prepare a blacklist file containing functions that should be ignored
SYMBOLS_FILE=/tmp/symbols-$(basename $EXEC)
readelf -sW $EXEC > $SYMBOLS_FILE || die "could not read symbol table"
BLACKLIST="$BLACKLIST_MUSL $EXTRA_BLACKLIST"
BLACKLIST_FILE=$EXEC.blacklist
rm -f $BLACKLIST_FILE
for func in $BLACKLIST; do
  grep "FUNC.*$func" $SYMBOLS_FILE | \
    awk '{printf "%s # %s\n", $2, $8}' >> $BLACKLIST_FILE
done

# Prepare an identity file containing functions that should be identity-randomized
IDENTITY_FILE=$EXEC.identity
for func in $IDENTITY; do
  grep "FUNC.*$func" $SYMBOLS_FILE | \
    awk '{printf "%s # %s\n", $2, $8}' >> $IDENTITY_FILE
done
rm -f $SYMBOLS_FILE

echo "Generated blacklist file '$BLACKLIST_FILE', pass to chameleon with -b"
if [[ "$IDENTITY" != "" ]]; then
  echo "Generated identity file '$IDENTITY_FILE', pass to chameleon with -i"
fi
