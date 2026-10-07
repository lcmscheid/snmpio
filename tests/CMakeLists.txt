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
  TestDisruptionMatrix.cpp
  TestError.cpp
  TestInterop.cpp
  TestInteropFaults.cpp
  TestInteropOperations.cpp
  TestInteropSet.cpp
  TestInteropV3.cpp
  TestInteropWalk.cpp
  TestOid.cpp
  TestPdu.cpp
  TestUsm.cpp
  TestV3Message.cpp
  TestValue.cpp)

target_link_libraries(snmpio_tests PRIVATE snmpio snmpio_warnings GTest::gtest GTest::gtest_main)
target_include_directories(snmpio_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(snmpio_tests PRIVATE ${SNMPIO_STDLIB_HARDENING})

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
