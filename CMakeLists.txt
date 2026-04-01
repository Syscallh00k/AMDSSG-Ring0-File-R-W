cmake_minimum_required(VERSION 4.1)
project(AMDSSG_Exploit)

set(CMAKE_CXX_STANDARD 20)

add_executable(AMDSSG_Exploit main.cpp)
target_link_libraries(AMDSSG_Exploit cfgmgr32)