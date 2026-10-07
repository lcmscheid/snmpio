# libFuzzer targets. Clang only -- GCC has no -fsanitize=fuzzer.
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR
    "SNMPIO_BUILD_FUZZERS requires Clang; configure with -DCMAKE_CXX_COMPILER=clang++.")
endif()

# -UNDEBUG because the asserts -- the fuzzers' and the library's they instrument -- are the oracles, and the build type -- RelWithDebInfo unless
# told otherwise -- defines NDEBUG and would compile every one of them out, leaving a fuzzer that
# only finds crashes. Target options come after the build type's flags, so this one wins.
add_library(snmpio_fuzz_options INTERFACE)
target_compile_options(snmpio_fuzz_options INTERFACE
  -g -O1 -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer
  -fno-sanitize-recover=undefined -UNDEBUG)
target_link_options(snmpio_fuzz_options INTERFACE -fsanitize=fuzzer,address,undefined)
target_compile_definitions(snmpio_fuzz_options INTERFACE
  ${SNMPIO_ASIO_NO_RECYCLING} ${SNMPIO_STDLIB_HARDENING})

# The library itself has to be instrumented, or coverage feedback sees nothing.
add_library(snmpio_fuzzed STATIC
  ${CMAKE_SOURCE_DIR}/src/BerReader.cpp
  ${CMAKE_SOURCE_DIR}/src/BerWriter.cpp
  ${CMAKE_SOURCE_DIR}/src/Client.cpp
  ${CMAKE_SOURCE_DIR}/src/Error.cpp
  ${CMAKE_SOURCE_DIR}/src/Oid.cpp
  ${CMAKE_SOURCE_DIR}/src/Pdu.cpp
  ${CMAKE_SOURCE_DIR}/src/Usm.cpp
  ${CMAKE_SOURCE_DIR}/src/V3Message.cpp
  ${CMAKE_SOURCE_DIR}/src/Value.cpp)
target_include_directories(snmpio_fuzzed PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(snmpio_fuzzed
  PUBLIC snmpio_fuzz_options ${SNMPIO_ASIO_TARGET} Threads::Threads PRIVATE OpenSSL::Crypto)
if(SNMPIO_ASIO_INCLUDE_DIRS)
  target_include_directories(snmpio_fuzzed SYSTEM PUBLIC ${SNMPIO_ASIO_INCLUDE_DIRS})
endif()
target_compile_features(snmpio_fuzzed PUBLIC cxx_std_20)
if(SNMP_USE_BOOST_ASIO)
  target_compile_definitions(snmpio_fuzzed PUBLIC SNMPIO_USE_BOOST_ASIO=1)
else()
  target_compile_definitions(snmpio_fuzzed PUBLIC ASIO_STANDALONE=1)
endif()

foreach(target FuzzBerValue FuzzBerVarbindList FuzzClient FuzzOidText FuzzV2cMessage FuzzV3Message)
  add_executable(${target} ${target}.cpp)
  target_link_libraries(${target} PRIVATE snmpio_fuzzed)
endforeach()

# FuzzClient's seeds are scripts for its Agent rather than datagrams, so they are a corpus of their
# own: the datagram fuzzers gain nothing from them, and FuzzClient nothing from datagrams.
add_custom_target(fuzz_corpus
  COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_CURRENT_SOURCE_DIR}/corpus ${CMAKE_CURRENT_BINARY_DIR}/corpus
  COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_CURRENT_SOURCE_DIR}/corpus-client ${CMAKE_CURRENT_BINARY_DIR}/corpus-client
  COMMENT "Staging the seed corpus")
