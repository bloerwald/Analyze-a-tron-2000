find_package (retdec REQUIRED COMPONENTS pelib)

add_executable (post_process_dumped_exe "post_process_dumped_exe.cpp")
target_link_libraries (post_process_dumped_exe PRIVATE retdec::pelib)
