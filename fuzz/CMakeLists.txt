# libFuzzer targets. Clang only -- GCC has no -fsanitize=fuzzer.
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR
    "SNMPIO_BUILD_FUZZERS requires Clang; configure with -DCMAKE_CXX_COMPILER=clang++.")
endif()

add_library(snmpio_fuzz_options INTERFACE)
target_compile_options(snmpio_fuzz_options INTERFACE
  -g -O1 -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer
  -fno-sanitize-recover=undefined)
target_link_options(snmpio_fuzz_options INTERFACE -fsanitize=fuzzer,address,undefined)

# The library itself has to be instrumented, or coverage feedback sees nothing.
add_library(snmpio_fuzzed STATIC
  ${CMAKE_SOURCE_DIR}/src/BerReader.cpp
  ${CMAKE_SOURCE_DIR}/src/BerWriter.cpp
  ${CMAKE_SOURCE_DIR}/src/Error.cpp
  ${CMAKE_SOURCE_DIR}/src/Oid.cpp
  ${CMAKE_SOURCE_DIR}/src/Value.cpp)
target_include_directories(snmpio_fuzzed PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(snmpio_fuzzed PUBLIC snmpio_fuzz_options)
target_compile_features(snmpio_fuzzed PUBLIC cxx_std_20)
if(SNMP_USE_BOOST_ASIO)
  target_compile_definitions(snmpio_fuzzed PUBLIC SNMPIO_USE_BOOST_ASIO=1)
endif()

foreach(target FuzzBerValue FuzzBerVarbindList FuzzOidText)
  add_executable(${target} ${target}.cpp)
  target_link_libraries(${target} PRIVATE snmpio_fuzzed)
endforeach()

add_custom_target(fuzz_corpus
  COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_CURRENT_SOURCE_DIR}/corpus ${CMAKE_CURRENT_BINARY_DIR}/corpus
  COMMENT "Staging the seed corpus")
