# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${PROJECT_SOURCE_DIR}/src/cc)
include_directories(${PROJECT_SOURCE_DIR}/src/cc/api)
if (CMAKE_USE_LIBBPF_PACKAGE AND LIBBPF_FOUND)
include_directories(${PROJECT_SOURCE_DIR}/src/cc/compat)
else()
include_directories(${PROJECT_SOURCE_DIR}/src/cc/libbpf/include/uapi)
endif()
include_directories(${PROJECT_SOURCE_DIR}/tests/python/include)
include_directories(${LLVM_INCLUDE_DIRS})

add_executable(test_static test_static.c)
if(NOT CMAKE_USE_LIBBPF_PACKAGE)
  target_link_libraries(test_static bcc-static)
else()
  target_link_libraries(test_static bcc-shared)
endif()

add_test(NAME c_test_static COMMAND ${TEST_WRAPPER} c_test_static sudo ${CMAKE_CURRENT_BINARY_DIR}/test_static)
add_compile_options(-DCMAKE_CURRENT_BINARY_DIR="${CMAKE_CURRENT_BINARY_DIR}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-result -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-result -fPIC")

if(${LLVM_PACKAGE_VERSION} VERSION_EQUAL 16 OR ${LLVM_PACKAGE_VERSION} VERSION_GREATER 16)
set(CMAKE_CXX_STANDARD 14)
endif()

if(ENABLE_USDT)
set(TEST_LIBBCC_SOURCES
	test_libbcc.cc
	test_c_api.cc
	test_array_table.cc
	test_bpf_table.cc
	test_cg_storage.cc
	test_hash_table.cc
	test_map_in_map.cc
	test_perf_event.cc
	test_pinned_table.cc
	test_prog_table.cc
	test_queuestack_table.cc
	test_shared_table.cc
	test_sk_storage.cc
	test_sock_table.cc
	test_usdt_args.cc
	test_usdt_probes.cc
	test_perf_buffer_poll_full_ring_buf.cc
	utils.cc
	test_parse_tracepoint.cc
	test_zip.cc)

file(COPY dummy_proc_map.txt DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
add_library(usdt_test_lib SHARED usdt_test_lib.cc)
add_library(debuginfo_test_lib SHARED debuginfo_test_lib.cc)

add_custom_command(OUTPUT debuginfo.so
                   COMMAND ${CMAKE_OBJCOPY}
                   ARGS --add-symbol debuginfo_only_symbol=.text:0
                   ${CMAKE_CURRENT_BINARY_DIR}/libdebuginfo_test_lib.so
                   ${CMAKE_CURRENT_BINARY_DIR}/debuginfo.so
                   DEPENDS debuginfo_test_lib)
add_custom_target(debuginfo DEPENDS debuginfo.so)

add_custom_command(OUTPUT with_gnu_debuglink.so
                   COMMAND ${CMAKE_OBJCOPY}
                   ARGS --add-gnu-debuglink=debuginfo.so
                   ${CMAKE_CURRENT_BINARY_DIR}/libdebuginfo_test_lib.so
                   ${CMAKE_CURRENT_BINARY_DIR}/with_gnu_debuglink.so
                   DEPENDS debuginfo debuginfo_test_lib)
add_custom_target(with_gnu_debuglink DEPENDS with_gnu_debuglink.so)
SET(DEBUGINFO_TARGETS debuginfo_test_lib debuginfo with_gnu_debuglink)

if(LIBLZMA_FOUND)
  add_custom_command(OUTPUT debuginfo.so.xz
                     COMMAND xz
                     ARGS -k ${CMAKE_CURRENT_BINARY_DIR}/debuginfo.so
                     DEPENDS debuginfo)
  add_custom_target(debuginfo_xz DEPENDS debuginfo.so.xz)

  add_custom_command(OUTPUT with_gnu_debugdata.so
                     COMMAND ${CMAKE_OBJCOPY}
                     ARGS --add-section .gnu_debugdata=${CMAKE_CURRENT_BINARY_DIR}/debuginfo.so.xz
                     ${CMAKE_CURRENT_BINARY_DIR}/libdebuginfo_test_lib.so
                     ${CMAKE_CURRENT_BINARY_DIR}/with_gnu_debugdata.so
                     DEPENDS debuginfo_xz debuginfo_test_lib)
  add_custom_target(with_gnu_debugdata DEPENDS with_gnu_debugdata.so)
  list(APPEND DEBUGINFO_TARGETS with_gnu_debugdata)
endif(LIBLZMA_FOUND)

add_custom_command(OUTPUT archive.zip
                   COMMAND mkdir -p zip_subdir
                   COMMAND echo "This is a text file" > zip_subdir/file.txt
                   COMMAND zip -0 archive.zip libdebuginfo_test_lib.so zip_subdir/file.txt
                   DEPENDS debuginfo_test_lib
                   BYPRODUCTS zip_subdir/file.txt)
add_custom_target(zip_archive DEPENDS archive.zip)

if(NOT CMAKE_USE_LIBBPF_PACKAGE)
  add_executable(test_libbcc ${TEST_LIBBCC_SOURCES})
  add_dependencies(test_libbcc bcc-shared zip_archive ${DEBUGINFO_TARGETS})

  target_link_libraries(test_libbcc ${PROJECT_BINARY_DIR}/src/cc/libbcc.so dl usdt_test_lib pthread)
  set_target_properties(test_libbcc PROPERTIES INSTALL_RPATH ${PROJECT_BINARY_DIR}/src/cc)
  target_compile_definitions(test_libbcc PRIVATE -DLIBBCC_NAME=\"libbcc.so\")

  add_test(NAME test_libbcc COMMAND ${TEST_WRAPPER} c_test_all sudo ${CMAKE_CURRENT_BINARY_DIR}/test_libbcc)
endif()

if(LIBBPF_FOUND)
  add_executable(test_libbcc_no_libbpf ${TEST_LIBBCC_SOURCES})
  add_dependencies(test_libbcc_no_libbpf bcc-shared zip_archive ${DEBUGINFO_TARGETS})

  target_link_libraries(test_libbcc_no_libbpf ${PROJECT_BINARY_DIR}/src/cc/libbcc.so dl usdt_test_lib ${LIBBPF_LIBRARIES} pthread)
  set_target_properties(test_libbcc_no_libbpf PROPERTIES INSTALL_RPATH ${PROJECT_BINARY_DIR}/src/cc)
  target_compile_definitions(test_libbcc_no_libbpf PRIVATE -DLIBBCC_NAME=\"libbcc.so\")

  add_test(NAME test_libbcc_no_libbpf COMMAND ${TEST_WRAPPER} c_test_all_no_libbpf sudo ${CMAKE_CURRENT_BINARY_DIR}/test_libbcc_no_libbpf)
endif()

endif(ENABLE_USDT)
