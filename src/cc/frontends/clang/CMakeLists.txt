# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DKERNEL_MODULES_DIR='\"${BCC_KERNEL_MODULES_DIR}\"'")
if(DEFINED BCC_CUR_CPU_IDENTIFIER)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCUR_CPU_IDENTIFIER='\"${BCC_CUR_CPU_IDENTIFIER}\"'")
endif()
if(DEFINED BCC_BACKUP_COMPILE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DBCC_BACKUP_COMPILE='${BCC_BACKUP_COMPILE}'")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DBCC_BACKUP_COMPILE=0")
endif()

add_library(clang_frontend-objects OBJECT loader.cc b_frontend_action.cc tp_frontend_action.cc kbuild_helper.cc)
add_library(clang_frontend STATIC $<TARGET_OBJECTS:clang_frontend-objects>)
