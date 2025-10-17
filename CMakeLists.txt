cmake_minimum_required(VERSION 3.10)
cmake_policy(SET CMP0167 NEW)

project(AES_CPP VERSION 1.0 LANGUAGES CXX)
enable_testing()

# =======================
#   CONFIGURATION GÉNÉRALE
# =======================

option(ENABLE_TESTS "Build unit tests" ON)
option(ENABLE_PYTHON_BINDING "Build Python binding" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Pour éviter les erreurs de type "recompile with -fPIC"
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include_directories(include)

# =======================
#   LIBRAIRIE PRINCIPALE
# =======================

file(GLOB_RECURSE SOURCES "src/*.cpp")
add_library(aes_lib STATIC ${SOURCES})

# Force la compilation en code position-indépendant
set_target_properties(aes_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_executable(AES_CPP main.cpp)

# =======================
#   BOOST
# =======================
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

# =======================
#   TESTS UNITAIRES
# =======================
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

# =======================
#   SOUS-PROJET UI (optionnel)
# =======================
add_subdirectory(aes_cpp_ui)

# =======================
#   PACKAGING (DEB)
# =======================
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Hugo Vitse")
set(CPACK_PACKAGE_NAME "aes-cpp")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_CONTACT "hugovitse1@gmail.com")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libboost-program-options1.74.0, libstdc++6")

install(TARGETS AES_CPP DESTINATION bin)
include(CPack)

# =======================
#   PYBIND11 BINDING
# =======================
if(ENABLE_PYTHON_BINDING)
    message(STATUS "Building Python bindings via pybind11")

    find_package(pybind11 REQUIRED)

    set(PYBIND11_SRC python_bindings.cpp)

    pybind11_add_module(aescpp ${PYBIND11_SRC})
    target_link_libraries(aescpp PRIVATE aes_lib)
    target_include_directories(aescpp PRIVATE include)

    # Installation du module Python dans le bon dossier
    # (Remplace "python3.X" par ta version, ex: python3.11)
    install(TARGETS aescpp
        LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python3.X/site-packages)
endif()
