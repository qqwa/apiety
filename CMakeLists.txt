cmake_minimum_required(VERSION 3.15)
project(apiety2)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(vendors/libtins)
add_subdirectory(vendors/spdlog)

add_executable(apiety2 src/main.cpp src/CaptureStreams.cpp src/CaptureStreams.h src/ReadMem.cpp src/ReadMem.h src/StreamFollower.cpp src/StreamFollower.h)

target_include_directories(apiety2 PRIVATE vendors/readerwriterqueue)
target_include_directories(apiety2 PRIVATE vendors/libtins/include)
target_include_directories(apiety2 PRIVATE ${PCAP_INCLUDE_DIR})
target_include_directories(apiety2 PRIVATE vendors/argh)
target_include_directories(apiety2 PRIVATE crypto/include)

target_link_libraries(apiety2 PRIVATE spdlog::spdlog tins)
if(UNIX AND NOT APPLE)
    target_link_libraries(apiety2 PRIVATE pthread)
endif()
if(WIN32)
    target_link_directories(apiety2 PRIVATE crypto/target/release)
    target_link_libraries(apiety2 PRIVATE  Ws2_32.lib Iphlpapi.lib ${PCAP_LIBRARY} userenv.lib crypto_rust)
endif()
