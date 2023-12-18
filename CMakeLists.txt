cmake_minimum_required(VERSION 3.4)

ENABLE_LANGUAGE(ASM_MASM)
set(ASM_DIALECT "-Masm")

set(CMAKE_CXX_STANDARD 17)

project(syscall)

add_library(syscall STATIC src/syscall.asm)

add_executable(syscall_example src/example.cpp)
target_include_directories(syscall_example PRIVATE include)
target_link_libraries(syscall_example syscall)
