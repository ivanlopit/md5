cmake_minimum_required(VERSION 3.5)

project(incr4k_md5 CXX)

set(VERSION_MAJOR 0)
set(VERSION_MINOR 1)
set(VERSION_PATCH 0)


option(GRCE_BUILD "use GRCE build suite" OFF)

add_subdirectory(src)

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/googletest)
    set(GTEST_FOUND_INDIR TRUE)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/googletest)
endif()

IF(GTEST_FOUND OR ${GTEST_FOUND_INDIR} OR ${GRCE_BUILD})
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tests)
endif()
