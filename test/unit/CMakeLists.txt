
set(TESTS
		test_spaces
		test_flag
		test_config
		test_sdb_archive
		test_anal)

foreach(test ${TESTS})
	add_executable(${test} "${test}.c")
	target_link_libraries(${test} core_r2db)
	add_test(NAME ${test} COMMAND ${test})
endforeach()