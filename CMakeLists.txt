cmake_minimum_required (VERSION 3.0)
enable_testing()

set (CMAKE_CXX_STANDARD 11)

add_library (util util/file.cpp util/iffchunk.cpp util/string.cpp)

add_executable (scan_chunks.exe scan_chunks.cpp)
target_link_libraries (scan_chunks.exe util)

file (GLOB_RECURSE scan_chunks_example_files
	"example_files/*.adt"
	"example_files/*.wdl"
	"example_files/*.wdt"
	"example_files/*.wmo"
	"example_files/*.tex"
	"example_files/*.m2"
	"example_files/*.anim"
	"example_files/*.phys"
	"example_files/*.skel"
)
message (STATUS ${scan_chunks_example_files})
add_test (NAME scan_chunks.test
	COMMAND $<TARGET_FILE:scan_chunks.exe> ${scan_chunks_example_files}
)
