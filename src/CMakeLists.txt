find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_library(ELF elf)
if (NOT ELF)
  message(FATAL_ERROR "libelf not found - please install libelf")
endif ()

# Find DynamoRIO installation.  Assumes installation has both Debug & Release
# builds a la release packages on the DynamoRIO webiste.
if (NOT DYNAMORIO_INSTALL_DIR)
  set(DYNAMORIO_INSTALL_DIR "/usr/lib")
endif ()
find_path(DYNAMORIO_INCLUDE_DIR
  NAMES dr_api.h
  PATHS ${DYNAMORIO_INSTALL_DIR}/include
)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(DYNAMORIO_LIB_TYPE ${DYNAMORIO_INSTALL_DIR}/lib64/debug)
else()
  set(DYNAMORIO_LIB_TYPE ${DYNAMORIO_INSTALL_DIR}/lib64/release)
endif()
find_path(DYNAMORIO_LIB_DIR
  NAMES libdrdecode.a
  PATHS ${DYNAMORIO_LIB_TYPE}
)
if (${DYNAMORIO_INCLUDE_DIR} STREQUAL "DYNAMORIO_INCLUDE_DIR-NOTFOUND" OR
    ${DYNAMORIO_LIB_DIR} STREQUAL "DYNAMORIO_LIB_DIR-NOTFOUND")
  message(FATAL_ERROR "DynamoRIO installation not found - please install and "
                      "set DYNAMORIO_INSTALL_DIR (see http://dynamorio.org/)")
endif ()

# Find compel installation.  Assumes installation has both Debug & Release
# builds -- see utils directory for script to configure & install both types of
# libcompel.a from CRIU source.
if (NOT COMPEL_INSTALL_DIR)
  set(COMPEL_INSTALL_DIR "/usr/lib")
endif()
find_path(COMPEL_INCLUDE_DIR
  NAMES compel/compel.h
  PATHS ${COMPEL_INSTALL_DIR}/include
)
find_path(COMPEL_BIN_DIR
  NAMES compel
  PATHS ${COMPEL_INSTALL_DIR}/bin
)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(COMPEL_LIB_TYPE ${COMPEL_INSTALL_DIR}/lib64/debug)
else()
  set(COMPEL_LIB_TYPE ${COMPEL_INSTALL_DIR}/lib64/release)
endif()
find_path(COMPEL_LIB_DIR
  NAMES libcompel.a
  PATHS ${COMPEL_LIB_TYPE}
)
if (${COMPEL_INCLUDE_DIR} STREQUAL "COMPEL_INCLUDE_DIR-NOTFOUND" OR
    ${COMPEL_BIN_DIR} STREQUAL "COMPEL_BIN_DIR-NOTFOUND" OR
    ${COMPEL_LIB_DIR} STREQUAL "COMPEL_LIB_DIR-NOTFOUND")
  message(FATAL_ERROR "compel not found - please download CRIU source, "
                      "install using helper scripts in the util folder and "
                      "set COMPEL_INSTALL_DIR")
endif()

# Find Secure Popcorn installation
if (NOT POPCORN_INSTALL_DIR)
  set(POPCORN_INSTALL_DIR "/usr/local/secure-popcorn")
endif ()
find_path(POPCORN_INCLUDE_DIR
  NAMES het_bin.h rewrite_metadata.h StackTransformTypes.def
  PATHS ${POPCORN_INSTALL_DIR}/include
)
if (${POPCORN_INCLUDE_DIR} STREQUAL "POPCORN_INCLUDE_DIR-NOTFOUND")
  message(FATAL_ERROR "Could not find Popcorn rewriting metadata headers - "
                      "please install and set POPCORN_INSTALL_DIR")
endif ()

# Pull in the target's register descriptions
EXECUTE_PROCESS(COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCH)
find_path(POPCORN_REGDESC_DIR
  NAMES regs.h
  PATHS ${POPCORN_INSTALL_DIR}/${ARCH}/include/arch/${ARCH}
)
if (${POPCORN_REGDESC_DIR} STREQUAL "POPCORN_REGDESC_DIR-NOTFOUND")
  message(FATAL_ERROR "Could not find ISA-specific register descriptions for "
                      "${ARCH} - please make sure the Popcorn compiler was "
                      "installed correctly at ${POPCORN_INSTALL_DIR}")
endif ()

# Create the parasite
execute_process (
  COMMAND ${COMPEL_BIN_DIR}/compel cflags
  OUTPUT_VARIABLE COMPEL_CFLAGS
)
set(COMPEL_CFLAGS "${COMPEL_CFLAGS} -O3 -I ${COMPEL_INCLUDE_DIR}/compel")
string(REGEX REPLACE "\n" ";" COMPEL_CFLAGS "${COMPEL_CFLAGS}")
string(REGEX REPLACE " " ";" COMPEL_CFLAGS "${COMPEL_CFLAGS}")
execute_process (
  COMMAND ${COMPEL_BIN_DIR}/compel ldflags
  OUTPUT_VARIABLE COMPEL_LDFLAGS
)
string(REGEX REPLACE "\n" ";" COMPEL_LDFLAGS "${COMPEL_LDFLAGS}")
string(REGEX REPLACE " " ";" COMPEL_LDFLAGS "${COMPEL_LDFLAGS}")
execute_process (
  COMMAND ${COMPEL_BIN_DIR}/compel plugins fds
  OUTPUT_VARIABLE COMPEL_PLUGINS
)
string(REGEX REPLACE "\n" ";" COMPEL_PLUGINS "${COMPEL_PLUGINS}")
string(REGEX REPLACE " " ";" COMPEL_PLUGINS "${COMPEL_PLUGINS}")
add_custom_command (OUTPUT ${CMAKE_BINARY_DIR}/include/chameleon-parasite.h
  COMMAND ${CMAKE_C_COMPILER} -c ${COMPEL_CFLAGS}
    -DPARASITE -I${PROJECT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/parasite/chameleon-parasite.c
    -o /tmp/chameleon-parasite.o
  COMMAND ld ${COMPEL_LDFLAGS} /tmp/chameleon-parasite.o ${COMPEL_PLUGINS}
    -o /tmp/chameleon-parasite.po
  COMMAND ${COMPEL_BIN_DIR}/compel hgen -f /tmp/chameleon-parasite.po
    -o ${CMAKE_BINARY_DIR}/include/chameleon-parasite.h
  COMMAND rm -f /tmp/chameleon-parasite.o /tmp/chameleon-parasite.po
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parasite/chameleon-parasite.c
  COMMENT "Generating chameleon-parasite.h header"
)
add_custom_target (parasite_lib
  DEPENDS ${CMAKE_BINARY_DIR}/include/chameleon-parasite.h
)

# Create the Chameleon executable
add_executable (chameleon
  arch.cpp
  binary.cpp
  chameleon.cpp
  memoryview.cpp
  parasite.cpp
  process.cpp
  randomize.cpp
  trace.cpp
  transform.cpp
  types.cpp
  userfaultfd.cpp
)
add_dependencies(chameleon parasite_lib)
target_include_directories (chameleon PRIVATE
  "${PROJECT_SOURCE_DIR}/include"
  "${DYNAMORIO_INCLUDE_DIR}"
  "${POPCORN_INCLUDE_DIR}"
  "${POPCORN_REGDESC_DIR}"
)
target_include_directories (chameleon SYSTEM PRIVATE "${COMPEL_INCLUDE_DIR}")
target_compile_options (chameleon PRIVATE
  "-std=c++11"
  "-pthread"
  "-Wall"
  "-Werror")
target_link_libraries (chameleon
  ${ELF}
  ${ZLIB_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  ${DYNAMORIO_LIB_DIR}/libdrdecode.a
  ${DYNAMORIO_LIB_DIR}/../libdrhelper.a
  ${COMPEL_LIB_DIR}/libcompel.a
  -static
)

if (CMAKE_BUILD_TYPE MATCHES "Debug")
  # This nasty define converts absolute paths to be relative to repository root
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
  target_compile_options (chameleon PRIVATE "-O0")
endif ()

