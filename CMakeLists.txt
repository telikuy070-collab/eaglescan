# CMakeLists.txt for Port Scanner Project

cmake_minimum_required(VERSION 3.10)  

# Set the project name  
project(PortScanner)  

# Set the C++ standard  
set(CMAKE_CXX_STANDARD 14)  
set(CMAKE_CXX_STANDARD_REQUIRED True)  

# Find required packages  
find_package(Threads REQUIRED)  

# Include directories  
include_directories(include)  

# Add the executable  
add_executable(port_scanner src/main.cpp)

# Link libraries  
target_link_libraries(port_scanner PRIVATE Threads::Threads)  

# Compiler flags  
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic")  
