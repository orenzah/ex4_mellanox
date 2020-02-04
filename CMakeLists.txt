cmake_minimum_required(VERSION 3.15)
project(ex4 C)

set(CMAKE_C_STANDARD 11)

link_libraries(ibverbs)
add_executable(client main.c main.c hash.h hash.c)
add_executable(server main.c hash.h hash.c)