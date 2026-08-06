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
  TestBerReader.cpp
  TestBerRoundtrip.cpp
  TestBerWriter.cpp
  TestError.cpp
  TestOid.cpp
  TestValue.cpp)

target_link_libraries(snmpio_tests PRIVATE snmpio snmpio_warnings GTest::gtest GTest::gtest_main)
target_include_directories(snmpio_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

include(GoogleTest)
gtest_discover_tests(snmpio_tests DISCOVERY_TIMEOUT 30)
