cmake_minimum_required(VERSION 3.12)

PROJECT (openssl-hello-world)

SET(SSL /usr/local/gmssl)
SET(CODEC ${PROJECT_SOURCE_DIR}/cppcodec)

#  /usr/include
INCLUDE_DIRECTORIES(
  ${CODEC}
  ${SSL}/include
  ${PROJECT_SOURCE_DIR}/include
)

LINK_DIRECTORIES(${SSL}/lib)

ADD_EXECUTABLE(sm2 sm2.cpp)
TARGET_LINK_LIBRARIES(sm2 crypto)

ADD_EXECUTABLE(mkcert mkcert/x509.cpp)
TARGET_LINK_LIBRARIES(mkcert crypto)