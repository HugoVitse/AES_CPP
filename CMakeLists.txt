cmake_minimum_required(VERSION 3.10)
cmake_policy(SET CMP0167 NEW)

project(AES_CPP)
enable_testing()

include_directories(include)

file(GLOB_RECURSE SOURCES "src/*.cpp")
add_library(aes_lib ${SOURCES})

add_executable(RUN main.cpp)
find_package(Boost REQUIRED COMPONENTS program_options)

target_link_libraries(RUN PRIVATE aes_lib Boost::program_options)


find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

file(GLOB_RECURSE TEST_SOURCES "tests/*.cpp")
add_executable(TESTS ${TEST_SOURCES})
target_link_libraries(TESTS aes_lib ${GTEST_LIBRARIES} gtest_main pthread Boost::program_options)

add_test(NAME run_tests COMMAND TESTS)
