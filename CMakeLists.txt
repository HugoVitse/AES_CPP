cmake_minimum_required(VERSION 3.10)

project(AES_CPP)

include_directories(include)

file(GLOB SOURCES "src/*.cpp")

add_executable(projet ${SOURCES})
