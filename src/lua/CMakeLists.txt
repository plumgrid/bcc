find_package(LuaJIT)
find_program(LUAJIT luajit)

if (LUAJIT_LIBRARIES AND LUAJIT)
	FILE(GLOB_RECURSE SRC_LUA
		${CMAKE_CURRENT_SOURCE_DIR}/bcc/*.lua
		${CMAKE_CURRENT_SOURCE_DIR}/bcc/vendor/*.lua
		${CMAKE_CURRENT_SOURCE_DIR}/bpf/*.lua)

	ADD_CUSTOM_COMMAND(
		OUTPUT bcc.lua
		COMMAND ${LUAJIT} ${CMAKE_CURRENT_SOURCE_DIR}/src/squish.lua ${CMAKE_CURRENT_SOURCE_DIR}
		DEPENDS ${SRC_LUA} ${CMAKE_CURRENT_SOURCE_DIR}/squishy
	)

	ADD_CUSTOM_COMMAND(
		OUTPUT bcc.o
		COMMAND ${LUAJIT} -bgd bcc.lua bcc.o
		DEPENDS bcc.lua
	)

	include_directories(${LUAJIT_INCLUDE_DIR})
	add_executable(bcc-lua src/main.c bcc.o)
	set_target_properties(bcc-lua PROPERTIES LINKER_LANGUAGE C)
	target_link_libraries(bcc-lua ${LUAJIT_LIBRARIES})
	target_link_libraries(bcc-lua ${bcc-lua-static})
	if (NOT COMPILER_NOPIE_FLAG EQUAL "")
		target_link_libraries(bcc-lua ${COMPILER_NOPIE_FLAG})
	endif()

	install(TARGETS bcc-lua RUNTIME DESTINATION bin)
endif()
