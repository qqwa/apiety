cmake_minimum_required(VERSION 3.15)
project(apiety2)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(vendors/libtins)
add_subdirectory(vendors/spdlog)

add_executable(apiety2 src/main.cpp src/CaptureStreams.cpp src/CaptureStreams.h)

target_include_directories(apiety2 PRIVATE vendors/readerwriterqueue)

target_link_libraries(apiety2 PRIVATE tins pthread)
target_link_libraries(apiety2 PRIVATE spdlog::spdlog)