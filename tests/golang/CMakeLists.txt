find_program(GO go)

if(RUN_GOLANG_TESTS)
	if(GO)
		add_test(NAME golang_test WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			COMMAND ${TEST_WRAPPER} golang_test sudo ${GO} test .)
	endif()
endif()
