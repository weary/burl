cmake_minimum_required (VERSION 2.8)

project(burl)

add_definitions(-Wall)
add_definitions(-ggdb3)
add_definitions(-std=c++0x)
add_definitions(-march=native)
add_definitions(-fPIC)

if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ggdb3")
endif()
if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUG")
	#	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GLIBCXX_DEBUG")
else()
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNDEBUG")
endif()


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

