cmake_minimum_required(VERSION 3.1)
project(LoadProcConfig)

include("ida-cmake/cmake/IDA.cmake")

set(sources "src/LoadProcConfig.cpp")
add_ida_plugin(${CMAKE_PROJECT_NAME} ${sources})