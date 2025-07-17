# Create the library
add_library(rlwe
    rlwe.cpp
)

# Add include directories
target_include_directories(rlwe
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link with OpenMP
target_link_libraries(rlwe PRIVATE OpenMP::OpenMP_CXX)

# Create an empty source file for now
file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/rlwe.cpp "")
