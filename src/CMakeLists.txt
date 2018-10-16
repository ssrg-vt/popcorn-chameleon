add_executable (chameleon
  binary.cpp
  chameleon.cpp
  process.cpp
  ptrace.cpp
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

target_include_directories (chameleon PRIVATE "${PROJECT_SOURCE_DIR}/include")
target_compile_options (chameleon PRIVATE "-std=c++11")
target_link_libraries (chameleon
  ${ELF}
  ${ZLIB_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  -static
)

if (CMAKE_BUILD_TYPE MATCHES "Debug")
  # This nasty define converts absolute paths to be relative to repository root
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
  target_compile_options (chameleon PRIVATE "-O0")
endif ()

