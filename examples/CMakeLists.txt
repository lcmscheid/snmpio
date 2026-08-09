# A standalone consumer project, not a subdirectory of the library's build. That is the point:
# building this is what proves the install rules and snmpioConfig.cmake actually work, so the
# examples and the package cannot rot apart from each other.
#
#   cmake --install build/default --prefix /usr/local
#   cmake -S examples -B build/examples -DCMAKE_PREFIX_PATH=/usr/local
#   cmake --build build/examples
cmake_minimum_required(VERSION 3.24)
project(snmpio-examples CXX)

find_package(snmpio REQUIRED)

foreach(example get walk)
  add_executable(example-${example} ${example}.cpp)
  target_link_libraries(example-${example} PRIVATE snmpio::snmpio)
endforeach()
