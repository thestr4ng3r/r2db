
set(TESTS
		test_spaces)

foreach(test ${TESTS})
	add_executable(${test} "${test}.c")
	target_link_libraries(${test} core_r2db)
endforeach()