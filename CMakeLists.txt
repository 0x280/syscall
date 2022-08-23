cmake_minimum_required(VERSION 3.4)
ENABLE_LANGUAGE(ASM_MASM)
set(ASM_DIALECT "-Masm")

project(syscall)
add_library(syscall "src/syscall.asm")