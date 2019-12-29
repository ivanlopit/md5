set(MD5_includes
        ${CMAKE_CURRENT_SOURCE_DIR}/../include/incr4k/md5/hasher.h
		${CMAKE_CURRENT_SOURCE_DIR}/transforms.hxx)

set(MD5_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/hasher.cpp)


add_library(md5
        ${MD5_includes}
        ${MD5_sources})


add_library(incr4k::md5 ALIAS md5)


target_include_directories(md5 
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>)