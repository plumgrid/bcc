# Copyright (c) Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${PROJECT_BINARY_DIR}/src/cc)
include_directories(${PROJECT_SOURCE_DIR}/src/cc)
include_directories(${PROJECT_SOURCE_DIR}/src/cc/api)
include_directories(${LLVM_INCLUDE_DIRS})

if (CMAKE_USE_LIBBPF_PACKAGE AND LIBBPF_FOUND)
include_directories(${PROJECT_SOURCE_DIR}/src/cc/compat)
else()
include_directories(${PROJECT_SOURCE_DIR}/src/cc/libbpf/include/uapi)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -shared")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -shared")

option(INSTALL_CPP_EXAMPLES "Install C++ examples. Those binaries are statically linked and can take plenty of disk space" OFF)

file(GLOB EXAMPLES *.cc)
foreach(EXAMPLE ${EXAMPLES})
  get_filename_component(NAME ${EXAMPLE} NAME_WE)
  add_executable(${NAME} ${EXAMPLE})

  if(NOT CMAKE_USE_LIBBPF_PACKAGE)
    target_link_libraries(${NAME} bcc-static)
  else()
    target_link_libraries(${NAME} bcc-shared)
  endif()

  if(INSTALL_CPP_EXAMPLES)
    install (TARGETS ${NAME} DESTINATION share/bcc/examples/cpp)
  endif(INSTALL_CPP_EXAMPLES)
endforeach()

add_subdirectory(pyperf)
