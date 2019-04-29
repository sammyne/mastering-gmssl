include(ExternalProject)

# cppcodec
SET(CPPCODEC_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/3rd_party/cppcodec)

ExternalProject_Add(cppcodec 
  GIT_PROGRESS 1 
  GIT_REPOSITORY https://github.com/tplgy/cppcodec.git 
  GIT_SHALLOW 1 
  GIT_TAG bd6ddf95129e769b50ef63e0f558fa21364f3f65 
  CMAKE_ARGS -D CMAKE_INSTALL_PREFIX=${CPPCODEC_PREFIX}  
  BUILD_IN_SOURCE 1)