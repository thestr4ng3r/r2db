
set(TESTS
		test_sdb_diff
		test_spaces)

set(COMMON_SRC
		sdb_diff.c)

add_library(test_common SHARED ${COMMON_SRC})
target_link_libraries(test_common core_r2db)

foreach(test ${TESTS})
	add_executable(${test} "${test}.c")
	target_link_libraries(${test} core_r2db test_common)
endforeach()