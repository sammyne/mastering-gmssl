cmake_minimum_required(VERSION 3.12)

PROJECT (gmssl-hello-world)

# 3rd_party dependencies
include(gmssl.cmake)
include(cppcodec.cmake)

include_directories(
  ${CPPCODEC_PREFIX}/include
  ${GMSSL_PREFIX}/include
)

link_directories(${GMSSL_PREFIX}/lib)

add_subdirectory(ssl)