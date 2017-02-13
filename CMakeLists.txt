project(ice)
cmake_minimum_required(VERSION 2.6)

set(PJNATH_SRC_ROOT ${CMAKE_SOURCE_DIR}/pjproject-2.5.5)

include_directories(${CMAKE_SOURCE_DIR}/public)
include_directories(${PJNATH_SRC_ROOT}/pjlib-util/include)
include_directories(${PJNATH_SRC_ROOT}/pjlib/include)
include_directories(${PJNATH_SRC_ROOT}/pjnath/include)

link_directories(${CMAKE_SOURCE_DIR}/pjsiplib)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

add_subdirectory(${CMAKE_SOURCE_DIR}/iceclient)
add_subdirectory(${CMAKE_SOURCE_DIR}/iceserver)
