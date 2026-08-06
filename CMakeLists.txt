cmake_minimum_required(VERSION 3.24)

project(snmpio
  VERSION 0.1.0
  DESCRIPTION "Async C++20 SNMPv2c/SNMPv3 command generator built directly on Asio"
  LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

include(CMakeDependentOption)
include(GNUInstallDirs)

set(SNMPIO_IS_TOP_LEVEL OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(SNMPIO_IS_TOP_LEVEL ON)
endif()

# ADR-0002: one source tree, either Asio. Boost.Asio is the default; standalone Asio is available
# to consumers who would rather not take a Boost dependency. CI must build both or the untested
# one rots.
option(SNMP_USE_BOOST_ASIO "Build against Boost.Asio rather than standalone Asio" ON)
option(SNMPIO_BUILD_TESTS "Build the unit tests" ${SNMPIO_IS_TOP_LEVEL})
option(SNMPIO_BUILD_FUZZERS "Build the libFuzzer targets (requires Clang)" OFF)
option(SNMPIO_SANITIZE "Enable address and undefined-behaviour sanitizers" OFF)
option(SNMPIO_WERROR "Treat warnings as errors" OFF)
option(SNMPIO_CLANG_TIDY "Run clang-tidy as part of the build" OFF)

# clang-tidy needs a compilation database whenever it is run out of band, so always emit one.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(SNMPIO_CLANG_TIDY)
  find_program(SNMPIO_CLANG_TIDY_EXE NAMES clang-tidy REQUIRED)
  set(CMAKE_CXX_CLANG_TIDY "${SNMPIO_CLANG_TIDY_EXE}")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
# Resolved now rather than at first use: the Asio choice appears in public headers, so a consumer
# that gets it wrong should find out at configure time, not from a wall of template errors.
if(SNMP_USE_BOOST_ASIO)
  # Boost.System has been header-only since 1.69 and some distributions no longer ship a
  # boost_system component at all, so ask for the component and fall back to Boost::headers.
  find_package(Boost 1.74 QUIET CONFIG OPTIONAL_COMPONENTS system)
  if(NOT Boost_FOUND)
    message(FATAL_ERROR
      "Boost.Asio was not found (need Boost >= 1.74).\n"
      "  Install it       -- Arch: pacman -S boost | Debian/Ubuntu: apt install libboost-dev\n"
      "  Or use standalone -- cmake --preset standalone  (equivalently -DSNMP_USE_BOOST_ASIO=OFF)\n"
      "The two are not interchangeable after the fact: the choice appears in every public "
      "signature. See docs/adr/0002-support-both-boost-asio-and-standalone-asio.md.")
  endif()
  if(TARGET Boost::system)
    set(SNMPIO_ASIO_TARGET Boost::system)
  else()
    set(SNMPIO_ASIO_TARGET Boost::headers)
  endif()
else()
  find_package(asio QUIET CONFIG)
  if(asio_FOUND)
    set(SNMPIO_ASIO_TARGET asio::asio)
  else()
    find_path(SNMPIO_ASIO_INCLUDE_DIR asio.hpp)
    if(NOT SNMPIO_ASIO_INCLUDE_DIR)
      message(FATAL_ERROR
        "Standalone Asio was not found.\n"
        "  Install it   -- Arch: pacman -S asio | Debian/Ubuntu: apt install libasio-dev\n"
        "  Or use Boost -- cmake --preset default   (equivalently -DSNMP_USE_BOOST_ASIO=ON)\n"
        "The two are not interchangeable after the fact: the choice appears in every public "
        "signature. See docs/adr/0002-support-both-boost-asio-and-standalone-asio.md.")
    endif()
    # A bare include directory rather than a wrapper target: an INTERFACE target would have to
    # be exported alongside the library, which would bake this machine's paths into the package.
    set(SNMPIO_ASIO_INCLUDE_DIRS "${SNMPIO_ASIO_INCLUDE_DIR}")
  endif()
endif()

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# The library
# ---------------------------------------------------------------------------
add_library(snmpio
  src/BerReader.cpp
  src/BerWriter.cpp
  src/Error.cpp
  src/Oid.cpp
  src/Value.cpp)
add_library(snmpio::snmpio ALIAS snmpio)

target_include_directories(snmpio
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_link_libraries(snmpio PUBLIC ${SNMPIO_ASIO_TARGET} Threads::Threads)
if(SNMPIO_ASIO_INCLUDE_DIRS)
  target_include_directories(snmpio SYSTEM PUBLIC
    $<BUILD_INTERFACE:${SNMPIO_ASIO_INCLUDE_DIRS}>)
endif()

target_compile_features(snmpio PUBLIC cxx_std_20)

if(SNMP_USE_BOOST_ASIO)
  target_compile_definitions(snmpio PUBLIC SNMPIO_USE_BOOST_ASIO=1)
else()
  target_compile_definitions(snmpio PUBLIC ASIO_STANDALONE=1)
endif()

set_target_properties(snmpio PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON)

add_library(snmpio_warnings INTERFACE)
if(MSVC)
  target_compile_options(snmpio_warnings INTERFACE /W4 $<$<BOOL:${SNMPIO_WERROR}>:/WX>)
else()
  target_compile_options(snmpio_warnings INTERFACE
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wold-style-cast
    -Wnon-virtual-dtor -Woverloaded-virtual -Wdouble-promotion
    $<$<BOOL:${SNMPIO_WERROR}>:-Werror>)
endif()
target_link_libraries(snmpio PRIVATE snmpio_warnings)

add_library(snmpio_sanitizers INTERFACE)
if(SNMPIO_SANITIZE AND NOT MSVC)
  target_compile_options(snmpio_sanitizers INTERFACE
    -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
  target_link_options(snmpio_sanitizers INTERFACE -fsanitize=address,undefined)
endif()
target_link_libraries(snmpio PUBLIC snmpio_sanitizers)

# ---------------------------------------------------------------------------
# Tests and fuzzers
# ---------------------------------------------------------------------------
if(SNMPIO_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(SNMPIO_BUILD_FUZZERS)
  add_subdirectory(fuzz)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
include(CMakePackageConfigHelpers)

install(TARGETS snmpio snmpio_warnings snmpio_sanitizers
  EXPORT snmpioTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT snmpioTargets
  FILE snmpioTargets.cmake
  NAMESPACE snmpio::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/snmpio)

configure_package_config_file(
  cmake/snmpioConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/snmpioConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/snmpio)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/snmpioConfigVersion.cmake"
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/snmpioConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/snmpioConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/snmpio)
