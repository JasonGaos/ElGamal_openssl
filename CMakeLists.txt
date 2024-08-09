cmake_minimum_required(VERSION 3.10)
project(ECExample)

set(CMAKE_CXX_STANDARD 11)

# Find OpenSSL library
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

# Source files
set(SOURCES
    src/ec_curve.cpp
    src/ec_elgamal.cpp
)

# Main executable
add_executable(ec_example src/main.cpp ${SOURCES})
target_link_libraries(ec_example OpenSSL::Crypto)

# Test executable
add_executable(test_curve test/test_curve.cpp ${SOURCES})
target_link_libraries(test_curve OpenSSL::Crypto)

add_executable(test_elgamal test/test_elgamal.cpp ${SOURCES})
target_link_libraries(test_elgamal OpenSSL::Crypto)