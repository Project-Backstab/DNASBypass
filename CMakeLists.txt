cmake_minimum_required(VERSION 3.16.3)

option (ATOMIZES_ENABLE_TESTS "Build tests for atomizes?" OFF)

add_subdirectory(third-party/atomizes)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
set(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -s")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s")

## BF2MC-Matchmaker
project(DNASBypass VERSION 1.0.0)

## Executable
add_executable(DNASBypass
	src/main.cpp
	src/logger.cpp
	src/net/socket.cpp
	src/util.cpp
	src/server.cpp
	src/dnasbypass/client.cpp
	src/urlrequest.cpp
)

target_include_directories(DNASBypass PUBLIC libs/openssl-1.0.2q/include src)
target_link_directories(DNASBypass PUBLIC libs/openssl-1.0.2q/lib)

find_library(SSL_LIBRARY ssl HINTS ${CMAKE_SOURCE_DIR}/libs/openssl-1.0.2q/lib)
find_library(CRYPTO_LIBRARY crypto HINTS ${CMAKE_SOURCE_DIR}/libs/openssl-1.0.2q/lib)
find_library(DL_LIBRARY dl)

target_link_libraries(DNASBypass PRIVATE ${SSL_LIBRARY} ${CRYPTO_LIBRARY} ${DL_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} atomizes)

## Version
execute_process(
    COMMAND git rev-parse --show-toplevel
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE PROJECT_GIT_TOPLEVEL
    OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
    COMMAND basename "${PROJECT_GIT_TOPLEVEL}"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE PROJECT_GIT_NAME
    OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
    COMMAND git rev-parse --abbrev-ref HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE PROJECT_GIT_BRANCH_NAME
    OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
    COMMAND git rev-parse HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE PROJECT_GIT_BRANCH_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
    COMMAND date
    OUTPUT_VARIABLE PROJECT_COMPILE_DATE
    OUTPUT_STRIP_TRAILING_WHITESPACE)

configure_file(src/version.h.in ${CMAKE_SOURCE_DIR}/src/version.h @ONLY)