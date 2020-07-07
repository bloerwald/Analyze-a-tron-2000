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
add_test (NAME scan_chunks.test
  COMMAND $<TARGET_FILE:scan_chunks.exe> ${scan_chunks_example_files}
)

add_subdirectory (glfw)

# \note This is probably the worst way to build all this, but shit I don't care
# anymore. It has been two hours now to get this work properly, with external
# projects, additional targets, and all. I just want it to work.
add_executable (meshtool.exe
  meshtool/glm/detail/glm.cpp
  meshtool/imgui.cpp
  meshtool/imgui_demo.cpp
  meshtool/imgui_draw.cpp
  meshtool/imgui_impl_glfw_gl3.cpp
  meshtool/main.cpp
  meshtool/libs/gl3w/GL/gl3w.c
  meshtool/libs/lua/src/lapi.c
  meshtool/libs/lua/src/lauxlib.c
  meshtool/libs/lua/src/lbaselib.c
  meshtool/libs/lua/src/lbitlib.c
  meshtool/libs/lua/src/lcode.c
  meshtool/libs/lua/src/lcorolib.c
  meshtool/libs/lua/src/lctype.c
  meshtool/libs/lua/src/ldblib.c
  meshtool/libs/lua/src/ldebug.c
  meshtool/libs/lua/src/ldo.c
  meshtool/libs/lua/src/ldump.c
  meshtool/libs/lua/src/lfunc.c
  meshtool/libs/lua/src/lgc.c
  meshtool/libs/lua/src/linit.c
  meshtool/libs/lua/src/liolib.c
  meshtool/libs/lua/src/llex.c
  meshtool/libs/lua/src/lmathlib.c
  meshtool/libs/lua/src/lmem.c
  meshtool/libs/lua/src/loadlib.c
  meshtool/libs/lua/src/lobject.c
  meshtool/libs/lua/src/lopcodes.c
  meshtool/libs/lua/src/loslib.c
  meshtool/libs/lua/src/lparser.c
  meshtool/libs/lua/src/lstate.c
  meshtool/libs/lua/src/lstring.c
  meshtool/libs/lua/src/lstrlib.c
  meshtool/libs/lua/src/ltable.c
  meshtool/libs/lua/src/ltablib.c
  meshtool/libs/lua/src/ltm.c
  meshtool/libs/lua/src/lundump.c
  meshtool/libs/lua/src/lutf8lib.c
  meshtool/libs/lua/src/lvm.c
  meshtool/libs/lua/src/lzio.c
)
target_include_directories (meshtool.exe PRIVATE
  ${CMAKE_SOURCE_DIR}/meshtool/
  ${CMAKE_SOURCE_DIR}/meshtool/libs/gl3w
  ${CMAKE_SOURCE_DIR}/meshtool/libs/glfw/include
)
target_link_libraries (meshtool.exe glfw)
#! \todo also to install, if this ever gets an install
file (COPY ${CMAKE_SOURCE_DIR}/meshtool/DroidSans.ttf
  DESTINATION ${CMAKE_BINARY_DIR}
)

add_executable (tablehash.exe tablehash.cpp)
