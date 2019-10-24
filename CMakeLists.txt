cmake_minimum_required(VERSION 3.12)

project(r2db)

option(R2DB_ENABLE_TESTS "Enable Tests for r2db" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(SOURCE
		include/r_project.h
		src/plugin.c
		src/project.c
		src/spaces.c
		src/flag.c)

list(APPEND SOURCE nxjson/nxjson.c)
include_directories(nxjson)

include_directories(include)

link_directories(${RADARE2_LIBRARY_DIRS})
add_library(core_r2db SHARED ${SOURCE})
set_target_properties(core_r2db PROPERTIES PREFIX "")

find_package(Radare2 REQUIRED)
target_include_directories(core_r2db PUBLIC ${RADARE2_INCLUDE_DIRS})
target_link_libraries(core_r2db PUBLIC ${RADARE2_LIBRARIES})

install(TARGETS core_r2db DESTINATION share/radare2/plugins)

if(R2DB_ENABLE_TESTS)
	add_subdirectory(test)
endif()