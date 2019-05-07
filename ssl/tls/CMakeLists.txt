cmake_minimum_required(VERSION 3.12)

project(tls13)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SRCS)

foreach(src ${SRCS})
  get_filename_component(out ${src} NAME_WE)

  add_executable(${out} ${src})
  target_link_libraries(${out} crypto ssl)
  add_dependencies(${out} ${thirdParty})
endforeach(src)