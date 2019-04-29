CMAKE_MINIMUM_REQUIRED(VERSION 3.12)

PROJECT(tls13)

ADD_EXECUTABLE(client client.cpp)
TARGET_LINK_LIBRARIES(client crypto ssl)

ADD_EXECUTABLE(server server.cpp)
TARGET_LINK_LIBRARIES(server crypto ssl)

ADD_EXECUTABLE(gencert gencert.cpp)
TARGET_LINK_LIBRARIES(gencert crypto ssl)