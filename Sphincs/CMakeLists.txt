add_executable(ClientSphincs clientSphincs.c)
add_executable(ServerSphincs serverSphincs.c)

target_include_directories(ClientSphincs PRIVATE
        ${CMAKE_SOURCE_DIR}/include/common
        ${CMAKE_SOURCE_DIR}/include/sphincs_utils
)
target_include_directories(ServerSphincs PRIVATE
        ${CMAKE_SOURCE_DIR}/include/common
        ${CMAKE_SOURCE_DIR}/include/sphincs_utils
)

find_package(OpenSSL REQUIRED)
target_link_libraries(ClientSphincs PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(ServerSphincs PRIVATE OpenSSL::SSL OpenSSL::Crypto)