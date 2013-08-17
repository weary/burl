cmake_minimum_required (VERSION 2.8)

project(burl)

add_definitions(-Wall)
add_definitions(-ggdb3)
add_definitions(-std=gnu++0x)
add_definitions(-march=native)

subdirs(reass)

add_library(http_parser http-parser/http_parser.c)

include_directories(reass)

add_executable(burl burl.cpp)
target_link_libraries(burl reass)
target_link_libraries(burl http_parser)

