cmake_minimum_required(VERSION 3.12)

PROJECT (gmssl-hello-world)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 3rd_party dependencies
set(thirdParty GmSSL cppcodec)

include(gmssl.cmake)
include(cppcodec.cmake)

include_directories(
  ${CPPCODEC_PREFIX}/include
  ${GMSSL_PREFIX}/include
)

link_directories(${GMSSL_PREFIX}/lib)


add_subdirectory(crypto)
add_subdirectory(ssl)