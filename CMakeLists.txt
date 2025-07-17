cmake_minimum_required(VERSION 3.10)
project(rlwe-signature 
        VERSION 0.1.0
        DESCRIPTION "RLWE Signature Scheme Implementation"
        LANGUAGES CXX)

# Require C++17 for better type support and features
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add compiler warnings
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Werror -pedantic)
endif()

# Option for building tests
option(BUILD_TESTS "Build test suite" ON)

# Find required packages
find_package(OpenMP REQUIRED)

# Add subdirectories
add_subdirectory(src)

# Add tests if enabled
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
