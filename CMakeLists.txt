cmake_minimum_required(VERSION 3.10)
cmake_policy(SET CMP0167 NEW)

project(AES_CPP VERSION 1.0 LANGUAGES CXX)
enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include_directories(include)

file(GLOB_RECURSE SOURCES "src/*.cpp")
add_library(aes_lib ${SOURCES})

add_executable(RUN main.cpp)

find_package(Boost REQUIRED COMPONENTS program_options)
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(RUN PRIVATE aes_lib Boost::program_options)
else()
    message(FATAL_ERROR "Boost not found")
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_libraries(RUN PRIVATE stdc++fs)
endif()

find_package(GTest REQUIRED)
if(GTEST_FOUND)
    include_directories(${GTEST_INCLUDE_DIRS})

    file(GLOB_RECURSE TEST_SOURCES "tests/*.cpp")
    add_executable(TESTS ${TEST_SOURCES})

    target_link_libraries(TESTS aes_lib ${GTEST_LIBRARIES} gtest_main pthread Boost::program_options)
    add_test(NAME run_tests COMMAND TESTS)
else()
    message(FATAL_ERROR "GoogleTest not found")
endif()
