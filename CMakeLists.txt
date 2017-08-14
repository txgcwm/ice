project(ice)

cmake_minimum_required(VERSION 2.6)

set(PJSIP_ROOT ${CMAKE_SOURCE_DIR}/3rdparty/prebuild/pjsip)

#include_directories(${CMAKE_SOURCE_DIR}/public)

include_directories(${PJSIP_ROOT}/include)
include_directories(${PJSIP_ROOT}/include/pjlib-util/)
include_directories(${PJSIP_ROOT}/include/pjnath/)

link_directories(${PJSIP_ROOT}/lib)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

add_subdirectory(${CMAKE_SOURCE_DIR}/iceclient)
add_subdirectory(${CMAKE_SOURCE_DIR}/iceserver)
