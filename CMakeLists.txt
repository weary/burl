cmake_minimum_required (VERSION 2.8)

project(burl)

add_definitions(-Wall)
add_definitions(-ggdb3)
add_definitions(-std=gnu++0x)
add_definitions(-march=native)

subdirs(reass)

add_library(http_parser http-parser/http_parser.c)

include_directories(reass)

add_library(burl
	burl.cpp
	packet_listener.cpp
	stream.cpp
	request_response.cpp
	)
target_link_libraries(burl reass)
target_link_libraries(burl http_parser)

add_executable(burl_test burl_test.cpp)
target_link_libraries(burl_test burl)

