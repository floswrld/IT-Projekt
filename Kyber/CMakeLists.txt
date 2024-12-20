add_executable(ClientKyber client.c)
add_executable(ServerKyber server.c)

target_include_directories(ClientKyber PRIVATE
        ${CMAKE_SOURCE_DIR}/include/common
        ${CMAKE_SOURCE_DIR}/include/kyber_utils
)
target_include_directories(ServerKyber PRIVATE
        ${CMAKE_SOURCE_DIR}/include/common
        ${CMAKE_SOURCE_DIR}/include/kyber_utils
)

find_package(OpenSSL REQUIRED)
target_link_libraries(ClientKyber PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(ServerKyber PRIVATE OpenSSL::SSL OpenSSL::Crypto)