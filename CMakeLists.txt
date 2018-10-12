cmake_minimum_required (VERSION 2.6)

project (PopcornChameleon)
set (PopcornChameleon_VERSION_MAJOR 0)
set (PopcornChameleon_VERSION_MINOR 1)

if (NOT CMAKE_SYSTEM_NAME MATCHES "Linux")
  message(FATAL_ERROR "Popcorn Chameleon only supports Linux")
endif ()
if (CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR "In-source builds are not allowed")
endif ()

if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "No build type selected, defaulting to Debug")
  set(CMAKE_BUILD_TYPE "Debug")
endif ()
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

configure_file (
  "${PROJECT_SOURCE_DIR}/include/config.h.in"
  "${PROJECT_BINARY_DIR}/include/config.h"
)
include_directories("${PROJECT_BINARY_DIR}/include")

add_subdirectory(src)

