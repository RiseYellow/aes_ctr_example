cmake_minimum_required(VERSION 3.6.0)
set(CMAKE_OSX_DEPLOYMENT_TARGET "10.9" CACHE STRING "Minimum OS X deployment version")
project(MediaWorkflow)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

set(CMAKE_CXX_STANDARD 14)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SRC)
add_executable(decrypto_test ${SRC})
target_link_libraries(decrypto_test ${CONAN_LIBS})