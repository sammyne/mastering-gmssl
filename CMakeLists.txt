cmake_minimum_required(VERSION 3.12)

PROJECT (gmssl-hello-world)

SET(SSL /usr/local/gmssl)
SET(CODEC ${PROJECT_SOURCE_DIR}/3rd_party/cppcodec)

INCLUDE_DIRECTORIES(
  ${CODEC}
  ${SSL}/include
  ${PROJECT_SOURCE_DIR}/include
)

LINK_DIRECTORIES(${SSL}/lib)

#ADD_EXECUTABLE(sm2 sm2.cpp)
#TARGET_LINK_LIBRARIES(sm2 crypto)
#
#ADD_EXECUTABLE(mkcert mkcert/x509.cpp)
#TARGET_LINK_LIBRARIES(mkcert crypto)

SET(MODULES 
  ${PROJECT_SOURCE_DIR}/crypto 
)

FOREACH( m ${MODULES} )
  GET_FILENAME_COMPONENT( moduleName ${m} NAME )
  #MESSAGE( "* ${moduleName}" )

  FILE(GLOB submodules ${m}/*)  
  FOREACH( sub ${submodules} )
    #MESSAGE( "-- ${sub}")

    GET_FILENAME_COMPONENT( submoduleName ${sub} NAME )
    #MESSAGE( "--- ${submoduleName}")

    FILE(GLOB sources ${sub}/*)  
    FOREACH( src ${sources} )

      GET_FILENAME_COMPONENT( out ${src} NAME_WE )
      SET(out ${moduleName}_${submoduleName}_${out})
      #MESSAGE(${out})

      ADD_EXECUTABLE( ${out} ${src} )
      TARGET_LINK_LIBRARIES(${out} crypto)
    ENDFOREACH( src )

  ENDFOREACH( sub )

ENDFOREACH( m )
