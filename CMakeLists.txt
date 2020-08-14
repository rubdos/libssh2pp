cmake_minimum_required (VERSION 3.1)
project(libssh2pp)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMakeModules")
set(CMAKE_COLOR_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 11)


if(CMAKE_COMPILER_IS_GNUCXX)
    list( APPEND CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -ftest-coverage -fprofile-arcs")
endif()

find_package(LibSSH2 REQUIRED)
include_directories(${LIBSSH2_INCLUDE_DIR})
message("This is the found include dir of libssh2:" ${LIBSSH2_INCLUDE_DIR})

add_executable(libssh2pp tests.cpp)
target_link_libraries(libssh2pp ${LIBSSH2_LIBRARY})
message(STATUS ${LIBSSH2_LIBRARY})

install(TARGETS libssh2pp RUNTIME DESTINATION bin)