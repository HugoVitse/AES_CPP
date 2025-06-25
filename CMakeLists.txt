cmake_minimum_required(VERSION 3.10)
cmake_policy(SET CMP0167 NEW)

project(AES_CPP VERSION 1.0 LANGUAGES CXX)
enable_testing()

option(ENABLE_TESTS "Build unit tests" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include_directories(include)

file(GLOB_RECURSE SOURCES "src/*.cpp")
add_library(aes_lib ${SOURCES})

add_executable(AES_CPP main.cpp)

find_package(Boost REQUIRED COMPONENTS program_options)
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(AES_CPP PRIVATE aes_lib Boost::program_options)
else()
    message(FATAL_ERROR "Boost not found")
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_libraries(AES_CPP PRIVATE stdc++fs)
endif()

if(ENABLE_TESTS)
    find_package(GTest REQUIRED)
    if(GTEST_FOUND)
        include_directories(${GTEST_INCLUDE_DIRS})

        file(GLOB_RECURSE TEST_SOURCES "tests/*.cpp")
        add_executable(TESTS ${TEST_SOURCES})

        target_link_libraries(TESTS aes_lib ${GTEST_LIBRARIES} gtest_main pthread Boost::program_options)
        add_test(NAME AES_CPP_tests COMMAND TESTS)
    else()
        message(FATAL_ERROR "GoogleTest not found")
    endif()
endif()

add_subdirectory(aes_cpp_ui)

set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Hugo Vitse")
set(CPACK_PACKAGE_NAME "aes-cpp")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_CONTACT "hugovitse1@gmail.com")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libboost-program-options1.74.0, libstdc++6")

install(TARGETS AES_CPP DESTINATION bin)
include(CPack)