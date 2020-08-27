cmake_minimum_required(VERSION 3.12)

project(r2db)

option(R2DB_ENABLE_TESTS "Enable Tests for r2db" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(SOURCE
		include/sdb_archive.h
		src/sdb_archive.c
		include/r_project.h
		include/r_serialize.h
		src/core_r2db.c
		src/project.c
		src/spaces.c
		src/flag.c
		src/core.c
		src/config.c
		src/anal.c)

include_directories(include)

link_directories(${RADARE2_LIBRARY_DIRS})
add_library(core_r2db SHARED ${SOURCE})
set_target_properties(core_r2db PROPERTIES PREFIX "")

find_package(Radare2 REQUIRED)
target_link_libraries(core_r2db PUBLIC Radare2::libr)

find_package(LibArchive REQUIRED)
target_include_directories(core_r2db PRIVATE ${LibArchive_INCLUDE_DIRS})
target_link_libraries(core_r2db PRIVATE ${LibArchive_LIBRARIES})

install(TARGETS core_r2db DESTINATION share/radare2/plugins)

if(R2DB_ENABLE_TESTS)
	enable_testing()
	add_subdirectory(test/unit)
endif()
