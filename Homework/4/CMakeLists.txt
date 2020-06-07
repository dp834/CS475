cmake_minimum_required(VERSION 3.10)
project(Homework4)


include_directories(Crypto)

find_package(OpenSSL 1.1.1)

find_package(Boost 1.65 COMPONENTS system thread)
include_directories(${Boost_INCLUDE_DIR})

add_executable(client Client.cpp)
target_link_libraries(client ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES})

add_executable(server Server.cpp)
target_link_libraries(server ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES})
