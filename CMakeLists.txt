cmake_minimum_required (VERSION 3.7)
project (base64 VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O -Wall -Wextra")

find_package(Boost 1.62.0 COMPONENTS unit_test_framework REQUIRED)

add_executable(${PROJECT_NAME} main.cc base64.cc)


add_executable(base64_test base64_test.cc base64.cc)

target_link_libraries(base64_test Boost::unit_test_framework) 
