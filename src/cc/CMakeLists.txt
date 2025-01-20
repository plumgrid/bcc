# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
# to be removed
include_directories(${CMAKE_CURRENT_BINARY_DIR}/frontends/b)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/frontends/b)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/frontends/clang)
include_directories(${LLVM_INCLUDE_DIRS})
include_directories(${LIBELF_INCLUDE_DIRS})
if (LIBLZMA_FOUND)
  include_directories(${LIBLZMA_INCLUDE_DIRS})
endif(LIBLZMA_FOUND)
if (LIBDEBUGINFOD_FOUND AND ENABLE_LIBDEBUGINFOD)
  include_directories(${LIBDEBUGINFOD_INCLUDE_DIRS})
endif (LIBDEBUGINFOD_FOUND AND ENABLE_LIBDEBUGINFOD)
# todo: if check for kernel version
if (CMAKE_USE_LIBBPF_PACKAGE AND LIBBPF_FOUND)
  include_directories(${LIBBPF_INCLUDE_DIRS})
else()
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/uapi)
endif()

# add_definitions has a problem parsing "-D_GLIBCXX_USE_CXX11_ABI=0", this is safer
separate_arguments(LLVM_DEFINITIONS)
add_compile_options(${LLVM_DEFINITIONS})

configure_file(libbcc.pc.in libbcc.pc @ONLY)
configure_file(bcc_version.h.in bcc_version.h @ONLY)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -DBCC_PROG_TAG_DIR='\"${BCC_PROG_TAG_DIR}\"'")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-result")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -Wno-unused-result")

if (NOT HAVE_REALLOCARRAY_SUPPORT)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPAT_NEED_REALLOCARRAY")
endif()

include(static_libstdc++)

if(LIBBPF_INCLUDE_DIR)
  # Add user libbpf include and notify compilation
  # that we are using external libbpf. It's checked
  # in src/cc/libbpf.h and proper files are included.
  include_directories(${LIBBPF_INCLUDE_DIR})
  add_definitions(-DHAVE_EXTERNAL_LIBBPF)
endif()

if(NOT CMAKE_USE_LIBBPF_PACKAGE)
  if(LIBBPF_FOUND)
    set(extract_dir ${CMAKE_CURRENT_BINARY_DIR}/libbpf_a_extract)
    execute_process(COMMAND sh -c "mkdir -p ${extract_dir} && cd ${extract_dir} && ${CMAKE_AR} x ${LIBBPF_STATIC_LIBRARIES}")
    file(GLOB libbpf_sources "${extract_dir}/*.o")
  else()
    file(GLOB libbpf_sources "libbpf/src/*.c")
  endif()

  set(libbpf_uapi libbpf/include/uapi/linux/)
endif()

set(bcc_common_sources bcc_common.cc bpf_module.cc bcc_btf.cc exported_files.cc)
if (${LLVM_PACKAGE_VERSION} VERSION_EQUAL 6 OR ${LLVM_PACKAGE_VERSION} VERSION_GREATER 6)
  set(bcc_common_sources ${bcc_common_sources} bcc_debug.cc)
endif()

if(ENABLE_LLVM_NATIVECODEGEN)
set(bcc_common_sources ${bcc_common_sources} bpf_module_rw_engine.cc)
else()
set(bcc_common_sources ${bcc_common_sources} bpf_module_rw_engine_disabled.cc)
endif()

set(bcc_table_sources table_storage.cc shared_table.cc bpffs_table.cc json_map_decl_visitor.cc)
set(bcc_util_sources common.cc)
set(bcc_sym_sources bcc_syms.cc bcc_elf.c bcc_perf_map.c bcc_proc.c bcc_zip.c)
set(bcc_common_headers libbpf.h perf_reader.h "${CMAKE_CURRENT_BINARY_DIR}/bcc_version.h")
set(bcc_table_headers file_desc.h table_desc.h table_storage.h)
set(bcc_api_headers bcc_common.h bpf_module.h bcc_exception.h bcc_syms.h bcc_proc.h bcc_elf.h)
if(LIBBPF_FOUND)
  set(bcc_common_sources ${bcc_common_sources} libbpf.c perf_reader.c)
endif()

if(ENABLE_CLANG_JIT)
add_library(bcc-shared SHARED
  link_all.cc ${bcc_common_sources} ${bcc_table_sources} ${bcc_sym_sources}
  ${bcc_util_sources})
set_target_properties(bcc-shared PROPERTIES VERSION ${REVISION_LAST} SOVERSION 0)
set_target_properties(bcc-shared PROPERTIES OUTPUT_NAME bcc)

if(ENABLE_USDT)
  add_definitions(-DEXPORT_USDT)
  set(bcc_usdt_sources usdt/usdt.cc usdt/usdt_args.cc)
  # else undefined
endif()

add_library(bcc-loader-static STATIC ${bcc_sym_sources} ${bcc_util_sources})
target_link_libraries(bcc-loader-static elf z)
add_library(bcc-static STATIC
  ${bcc_common_sources} ${bcc_table_sources} ${bcc_util_sources} ${bcc_usdt_sources} ${bcc_sym_sources} ${bcc_util_sources})
set_target_properties(bcc-static PROPERTIES OUTPUT_NAME bcc)
set(bcc-lua-static
  ${bcc_common_sources} ${bcc_table_sources} ${bcc_sym_sources} ${bcc_util_sources})

set(bpf_sources libbpf.c perf_reader.c ${libbpf_sources} ${bcc_sym_sources} ${bcc_util_sources} ${bcc_usdt_sources})
add_library(bpf-static STATIC ${bpf_sources})
set_target_properties(bpf-static PROPERTIES OUTPUT_NAME bcc_bpf)
target_link_libraries(bpf-static elf z)
add_library(bpf-shared SHARED ${bpf_sources})
set_target_properties(bpf-shared PROPERTIES VERSION ${REVISION_LAST} SOVERSION 0)
set_target_properties(bpf-shared PROPERTIES OUTPUT_NAME bcc_bpf)
target_link_libraries(bpf-shared elf z)
if(LIBLZMA_FOUND)
  target_link_libraries(bpf-shared ${LIBLZMA_LIBRARIES})
endif(LIBLZMA_FOUND)
if(LIBDEBUGINFOD_FOUND)
  target_link_libraries(bpf-shared ${LIBDEBUGINFOD_LIBRARIES})
endif(LIBDEBUGINFOD_FOUND)
if(CMAKE_USE_LIBBPF_PACKAGE AND LIBBPF_FOUND)
  target_link_libraries(bpf-shared ${LIBBPF_LIBRARIES})
endif()

include(clang_libs)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${clang_lib_exclude_flags}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${llvm_lib_exclude_flags}")

# bcc_common_libs_for_a for archive libraries
# bcc_common_libs_for_s for shared libraries
set(bcc_common_libs clang_frontend
  -Wl,--whole-archive ${clang_libs} ${llvm_libs} -Wl,--no-whole-archive
  ${LIBELF_LIBRARIES})
if (LIBLZMA_FOUND)
  list(APPEND bcc_common_libs ${LIBLZMA_LIBRARIES})
endif (LIBLZMA_FOUND)
if (LIBDEBUGINFOD_FOUND)
  list(APPEND bcc_common_libs ${LIBDEBUGINFOD_LIBRARIES})
endif (LIBDEBUGINFOD_FOUND)
set(bcc_common_libs_for_a ${bcc_common_libs})
set(bcc_common_libs_for_s ${bcc_common_libs})
set(bcc_common_libs_for_lua clang_frontend
  ${clang_libs} ${llvm_libs} ${LIBELF_LIBRARIES})
if(LIBBPF_FOUND)
  list(APPEND bcc_common_libs_for_a ${LIBBPF_LIBRARIES})
  list(APPEND bcc_common_libs_for_s ${LIBBPF_LIBRARIES})
  list(APPEND bcc_common_libs_for_lua ${LIBBPF_LIBRARIES})
else()
  list(APPEND bcc_common_libs_for_a bpf-static)
  list(APPEND bcc_common_libs_for_s bpf-static)
  list(APPEND bcc_common_libs_for_lua bpf-static)
endif()

if(ENABLE_CPP_API)
  add_subdirectory(api)
  target_sources(bcc-static PRIVATE $<TARGET_OBJECTS:api-objects>)
  # Keep all API functions
  list(APPEND bcc_common_libs_for_s -Wl,--whole-archive api-static -Wl,--no-whole-archive)
endif()

if(ENABLE_USDT)
  list(APPEND bcc_api_headers bcc_usdt.h)
  add_subdirectory(usdt)
  list(APPEND bcc_common_libs_for_a usdt-static)
  list(APPEND bcc_common_libs_for_s usdt-static)
  list(APPEND bcc_common_libs_for_lua usdt-static)
endif()

add_subdirectory(frontends)

target_sources(bcc-static PRIVATE $<TARGET_OBJECTS:clang_frontend-objects>)

# Link against LLVM libraries
target_link_libraries(bcc-shared ${bcc_common_libs_for_s})
target_link_libraries(bcc-static ${bcc_common_libs_for_a} bcc-loader-static)
set(bcc-lua-static ${bcc-lua-static} ${bcc_common_libs_for_lua})

install(TARGETS bcc-shared bcc-static bcc-loader-static bpf-static LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${bcc_table_headers} DESTINATION include/bcc)
install(FILES ${bcc_api_headers} DESTINATION include/bcc)
install(DIRECTORY ${libbpf_uapi} DESTINATION include/bcc/compat/linux FILES_MATCHING PATTERN "*.h")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libbcc.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif(ENABLE_CLANG_JIT)
install(FILES ${bcc_common_headers} DESTINATION include/bcc)
install(TARGETS bpf-shared LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
