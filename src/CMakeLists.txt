add_executable (chameleon
  arch.cpp
  binary.cpp
  chameleon.cpp
  memoryview.cpp
  process.cpp
  trace.cpp
  transform.cpp
  types.cpp
  userfaultfd.cpp
)

find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_library(ELF elf)
if (NOT ELF)
  message(FATAL_ERROR "libelf not found - please install libelf")
endif ()

# Find Capstone installation
if (NOT CAPSTONE_INSTALL_DIR)
  set(CAPSTONE_INSTALL_DIR "/usr/lib")
endif ()
find_path(CAPSTONE_INCLUDE_DIR
  NAMES capstone/capstone.h
  PATHS ${CAPSTONE_INSTALL_DIR}/include
)
find_path(CAPSTONE_LIB_DIR
  NAMES libcapstone.a
  PATHS ${CAPSTONE_INSTALL_DIR}/lib
)
if (${CAPSTONE_INCLUDE_DIR} STREQUAL "CAPSTONE_INCLUDE_DIR-NOTFOUND" OR
    ${CAPSTONE_LIB_DIR} STREQUAL "CAPSTONE_LIB_DIR-NOTFOUND")
  message(FATAL_ERROR "Capstone installation not found - please install and "
                      "set CAPSTONE_INSTALL_DIR (see "
                      "http://www.capstone-engine.org/)")
endif ()

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

target_include_directories (chameleon PRIVATE
  "${PROJECT_SOURCE_DIR}/include"
  "${CAPSTONE_INCLUDE_DIR}"
  "${POPCORN_INCLUDE_DIR}"
)
target_compile_options (chameleon PRIVATE "-std=c++11" "-pthread")
target_link_libraries (chameleon
  ${ELF}
  ${ZLIB_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  ${CAPSTONE_LIB_DIR}/libcapstone.a
  -static
)

if (CMAKE_BUILD_TYPE MATCHES "Debug")
  # This nasty define converts absolute paths to be relative to repository root
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
  target_compile_options (chameleon PRIVATE "-O0")
endif ()

