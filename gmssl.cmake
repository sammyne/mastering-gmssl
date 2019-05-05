include(ExternalProject)

# GmSSL
SET(GMSSL_PREFIX ${CMAKE_SOURCE_DIR}/3rd_party/gmssl) 
ExternalProject_Add(GmSSL 
  GIT_PROGRESS 1 
  GIT_REPOSITORY https://github.com/guanzhi/GmSSL.git 
  GIT_SHALLOW 1  
  GIT_TAG 4a20b5f54c0a313ce998d8ecc5dd8f34c5c4c1b4 
  CONFIGURE_COMMAND ./config --prefix=${GMSSL_PREFIX} no-weak-ssl-ciphers enable-ec_nistp_64_gcc_128 
  BUILD_IN_SOURCE 1)