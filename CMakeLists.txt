cmake_minimum_required(VERSION 3.17)
project(IT-Projekt LANGUAGES C)

set(CMAKE_C_STANDARD 17)

add_subdirectory(Kyber)
add_subdirectory(Sphincs)

include_directories(include)