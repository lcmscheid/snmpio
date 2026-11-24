find_package(GTest QUIET CONFIG)

if(NOT GTest_FOUND)
  include(FetchContent)
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.17.0
    GIT_SHALLOW ON)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
endif()

# The library the tests link. They reach past the public API -- detail/'s Views, src/'s private
# headers -- and a shared snmpio exports only what a consumer of the installed headers needs
# (#106). So a shared build compiles a static copy of the sources for them, as fuzz/ does for its
# instrumented one, configured as snmpio is in everything but its visibility; a static build links
# snmpio itself rather than compile the sources twice.
get_target_property(SNMPIO_LIBRARY_TYPE snmpio TYPE)
if(SNMPIO_LIBRARY_TYPE STREQUAL "SHARED_LIBRARY")
  add_library(snmpio_tested STATIC ${SNMPIO_SOURCES})
  snmpio_configure_library(snmpio_tested)
  target_link_libraries(snmpio_tested PUBLIC snmpio_sanitizers PRIVATE snmpio_warnings)
  snmpio_harden(snmpio_tested)
  set(SNMPIO_TEST_LIBRARY snmpio_tested)
else()
  set(SNMPIO_TEST_LIBRARY snmpio)
endif()

add_executable(snmpio_tests
  FailingAllocation.cpp
  InteropSummary.cpp
  TestBerReader.cpp
  TestBerRoundtrip.cpp
  TestBerWriter.cpp
  TestClient.cpp
  TestClientExceptions.cpp
  TestClientLifetime.cpp
  TestClientV3.cpp
  TestCompilerHardening.cpp
  TestDisruptionMatrix.cpp
  TestError.cpp
  TestInterop.cpp
  TestInteropFaults.cpp
  TestInteropOperations.cpp
  TestInteropSet.cpp
  TestInteropV3.cpp
  TestInteropWalk.cpp
  TestMessageIdGenerator.cpp
  TestMessageIds.cpp
  TestOid.cpp
  TestOutstanding.cpp
  TestPdu.cpp
  TestSecrets.cpp
  TestSoakPlan.cpp
  TestStdlibHardening.cpp
  TestUsm.cpp
  TestV3Message.cpp
  TestValue.cpp)

target_link_libraries(snmpio_tests PRIVATE
  ${SNMPIO_TEST_LIBRARY} snmpio_warnings GTest::gtest GTest::gtest_main)
target_include_directories(snmpio_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
# TestMessageIdGenerator.cpp tests src/MessageIdGenerator.hpp directly, a header that is not
# installed, and hands it OpenSSL library contexts of its own to fail in. The private headers are
# on that one file's include path, not the whole binary's.
set_property(SOURCE TestMessageIdGenerator.cpp APPEND PROPERTY INCLUDE_DIRECTORIES
  ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(snmpio_tests PRIVATE OpenSSL::Crypto)
snmpio_harden(snmpio_tests)
# Whether SNMPIO_HARDENING is on: CompilerHardening's test skips without it.
target_compile_definitions(snmpio_tests PRIVATE
  SNMPIO_TESTS_HARDENED=$<BOOL:${SNMPIO_HARDENING}>)

# FailingAllocation.cpp replaces the global operator new. Clang links a sanitizer runtime into the
# binary whole, its own operator new included, so a binary built with one cannot replace it too;
# GCC's runtimes are shared libraries, which the replacement overrides. Without it, the tests that
# need it skip.
if(SNMPIO_TSAN OR (SNMPIO_SANITIZE AND CMAKE_CXX_COMPILER_ID MATCHES "Clang"))
  target_compile_definitions(snmpio_tests PRIVATE SNMPIO_TESTS_REPLACE_OPERATOR_NEW=0)
else()
  target_compile_definitions(snmpio_tests PRIVATE SNMPIO_TESTS_REPLACE_OPERATOR_NEW=1)
endif()

include(GoogleTest)
gtest_discover_tests(snmpio_tests DISCOVERY_TIMEOUT 30)

# The soak (#32) is a binary of its own so that it can carry the `stress` label: `ctest -L stress`
# runs it alone, `ctest -LE stress` everything else. It runs for two seconds unless
# SNMPIO_SOAK_SECONDS says otherwise, so it stays in the default run.
add_executable(snmpio_stress TestSoak.cpp)
target_link_libraries(snmpio_stress PRIVATE
  ${SNMPIO_TEST_LIBRARY} snmpio_warnings GTest::gtest GTest::gtest_main)
target_include_directories(snmpio_stress PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
snmpio_harden(snmpio_stress)
gtest_discover_tests(snmpio_stress DISCOVERY_TIMEOUT 30 PROPERTIES LABELS stress)
