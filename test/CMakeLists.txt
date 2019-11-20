
set(TESTS
		test_spaces
		test_flag
		test_sdb_archive)

foreach(test ${TESTS})
	add_executable(${test} "${test}.c")
	target_link_libraries(${test} core_r2db)
endforeach()