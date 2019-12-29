set(MD5_TESTS_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp 
        ${CMAKE_CURRENT_SOURCE_DIR}/test_api.cpp)

add_executable(md5_tests ${MD5_TESTS_sources})

target_link_libraries(md5_tests incr4k::md5 gtest)