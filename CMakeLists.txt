cmake_minimum_required(VERSION 3.17)
project(IT-Projekt LANGUAGES C)

set(CMAKE_C_STANDARD 17)

add_executable(ClientKyber src/Kyber/client.c
        src/Kyber/api_kyber.h
        src/Kyber/api_sphincs.h)
add_executable(ServerKyber src/Kyber/server.c
        src/Kyber/api_kyber.h
        src/Kyber/api_sphincs.h)
add_executable(ClientSphincs src/Sphincs/clientSphincs.c
        src/Kyber/api_kyber.h
        src/Kyber/api_sphincs.h)
add_executable(ServerSphincs src/Sphincs/serverSphincs.c
        src/Kyber/api_kyber.h
        src/Kyber/api_sphincs.h)

find_package(OpenSSL REQUIRED)
target_link_libraries(ClientKyber PRIVATE OpenSSL::SSL OpenSSL::Crypto)