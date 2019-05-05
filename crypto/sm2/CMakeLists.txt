cmake_minimum_required(VERSION 3.12)

project(sm2)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SM2_SRCS)

foreach(src ${SM2_SRCS})
  get_filename_component(out ${src} NAME_WE)

  add_executable(${out} ${src})
  target_link_libraries(${out} crypto)
  add_dependencies(${out} ${thirdParty})
endforeach(src)