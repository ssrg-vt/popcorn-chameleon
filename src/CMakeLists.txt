add_executable (chameleon chameleon.cpp process.cpp ptrace.cpp types.cpp)
target_include_directories (chameleon PRIVATE "${PROJECT_SOURCE_DIR}/include")
target_compile_options (chameleon PRIVATE "-std=c++11")
if (CMAKE_BUILD_TYPE MATCHES "Debug")
  # This nasty define converts absolute paths to be relative to repository root
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
  target_compile_options (chameleon PRIVATE "-O0")
endif ()

