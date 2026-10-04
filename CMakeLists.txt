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
option(SNMPIO_TSAN "Enable the thread sanitizer (Clang; not together with SNMPIO_SANITIZE)" OFF)
option(SNMPIO_WERROR "Treat warnings as errors" OFF)
option(SNMPIO_CLANG_TIDY "Run clang-tidy as part of the build" OFF)

# TSan and ASan cannot share a process, and GCC with TSan cannot build Asio warning-free: it warns
# that TSan does not model std::atomic_thread_fence, which Asio's fenced blocks use (research note
# 4.2). Clang is the one compiler the TSan build is tested with.
if(SNMPIO_TSAN AND SNMPIO_SANITIZE)
  message(FATAL_ERROR "SNMPIO_TSAN and SNMPIO_SANITIZE cannot be combined; pick one.")
endif()
if(SNMPIO_TSAN AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "SNMPIO_TSAN requires Clang; configure with -DCMAKE_CXX_COMPILER=clang++.")
endif()

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
# Asio's own macros and headers carry the flavour's prefix -- BOOST_ASIO_VERSION and
# <boost/asio/version.hpp> under Boost, ASIO_VERSION and <asio/version.hpp> standalone -- and the
# sanitizer builds below name both.
if(SNMP_USE_BOOST_ASIO)
  set(SNMPIO_ASIO_MACRO_PREFIX BOOST_ASIO)
  set(SNMPIO_ASIO_HEADER_PREFIX boost/asio)
  # Boost.System has been header-only since 1.69 and some distributions no longer ship a
  # boost_system component at all, so ask for the component and fall back to Boost::headers.
  find_package(Boost 1.77 QUIET CONFIG OPTIONAL_COMPONENTS system)
  if(NOT Boost_FOUND)
    message(FATAL_ERROR
      "Boost.Asio was not found (need Boost >= 1.77, for per-operation cancellation).\n"
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
  set(SNMPIO_ASIO_MACRO_PREFIX ASIO)
  set(SNMPIO_ASIO_HEADER_PREFIX asio)
  # 1.21 is where per-operation cancellation arrived, which the Walk's total/terminal split needs.
  # Only the CONFIG path can be checked; the include-directory fallback below is a bare header
  # tree with no version to read.
  find_package(asio 1.21 QUIET CONFIG)
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

# ADR-0001: the crypto is OpenSSL EVP's, not ours. Required rather than optional -- SNMPv3 is the
# reason this library exists, and a build with USM silently missing would be a trap.
find_package(OpenSSL 3.0 REQUIRED)

# ---------------------------------------------------------------------------
# The library
# ---------------------------------------------------------------------------
add_library(snmpio
  src/BerReader.cpp
  src/BerWriter.cpp
  src/Client.cpp
  src/Error.cpp
  src/Oid.cpp
  src/Pdu.cpp
  src/Usm.cpp
  src/V3Message.cpp
  src/Value.cpp)
add_library(snmpio::snmpio ALIAS snmpio)

target_include_directories(snmpio
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_link_libraries(snmpio PUBLIC ${SNMPIO_ASIO_TARGET} Threads::Threads)
# Private: no public header names an OpenSSL type. Consumers still need the package found, which
# is why snmpioConfig.cmake finds it -- a static archive carries its private links to the linker.
target_link_libraries(snmpio PRIVATE OpenSSL::Crypto)
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
# /we4062 and -Werror=switch are not gated on SNMPIO_WERROR: the classification switches in
# Error.cpp have no default so that a newly added Errc fails the build rather than silently
# classifying as Unclassified. A warning nobody opted into would not do that.
if(MSVC)
  target_compile_options(snmpio_warnings INTERFACE /W4 /we4062 $<$<BOOL:${SNMPIO_WERROR}>:/WX>)
else()
  target_compile_options(snmpio_warnings INTERFACE
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wold-style-cast
    -Wnon-virtual-dtor -Woverloaded-virtual -Wdouble-promotion -Werror=switch
    $<$<BOOL:${SNMPIO_WERROR}>:-Werror>)
endif()
target_link_libraries(snmpio PRIVATE snmpio_warnings)

# Standard-library hardening: bounds-checked operator[], front() on an empty container and the like
# abort instead of reading past the end (research note 5.2). Both are ABI-neutral, so a consumer
# built without them links against this library unchanged. PRIVATE on our own targets only --
# imposing them through the exported interface would be choosing a consumer's build flags. Each
# macro is ignored by the other library, so both are set whichever is in use. A list rather than an
# INTERFACE target: a target linked even PRIVATE to a static library is exported with it, and its
# definitions would then sit in the installed snmpioTargets.cmake.
set(SNMPIO_STDLIB_HARDENING
  _GLIBCXX_ASSERTIONS
  _LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST)
target_compile_definitions(snmpio PRIVATE ${SNMPIO_STDLIB_HARDENING})

# Asio hands freed handler and coroutine-frame memory to a thread-local cache and reuses it, so a
# use-after-free in a sanitizer build touches a live recycled block and goes unreported. None of
# these macros is in Asio's documented macro table. The two DISABLE ones are read in
# detail/recycling_allocator.hpp and impl/awaitable.hpp (research note 4.1), but the small-block one
# is absent from Asio 1.28.1 and 1.30.2, and CI's Ubuntu ships 1.28.1. So the cache is also sized to
# zero: detail/thread_info_base.hpp reads the size in 1.28.1 and 1.38.2 alike, the cache's loops are
# then empty, and every block goes straight back to the heap. That size makes Asio declare a
# zero-length array, a GNU extension -Wpedantic would flag were Asio's headers not system ones.
# Every sanitizer build defines these -- ASan, TSan and the fuzzers.
set(SNMPIO_ASIO_NO_RECYCLING
  ${SNMPIO_ASIO_MACRO_PREFIX}_DISABLE_AWAITABLE_FRAME_RECYCLING
  ${SNMPIO_ASIO_MACRO_PREFIX}_DISABLE_SMALL_BLOCK_RECYCLING
  ${SNMPIO_ASIO_MACRO_PREFIX}_RECYCLING_ALLOCATOR_CACHE_SIZE=0)

# Public, so everything linking snmpio is built the same way: a recycling-off translation unit
# freeing a frame a recycling-on one allocated would be the mismatch the macros exist to avoid.
add_library(snmpio_sanitizers INTERFACE)
if(SNMPIO_SANITIZE AND NOT MSVC)
  target_compile_options(snmpio_sanitizers INTERFACE
    -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
  target_link_options(snmpio_sanitizers INTERFACE -fsanitize=address,undefined)
  target_compile_definitions(snmpio_sanitizers INTERFACE ${SNMPIO_ASIO_NO_RECYCLING})
endif()
if(SNMPIO_TSAN)
  target_compile_options(snmpio_sanitizers INTERFACE -fsanitize=thread -fno-omit-frame-pointer)
  target_link_options(snmpio_sanitizers INTERFACE -fsanitize=thread)
  target_compile_definitions(snmpio_sanitizers INTERFACE ${SNMPIO_ASIO_NO_RECYCLING})
  # TSan does not model std::atomic_thread_fence, which Asio's fenced blocks are built on, so
  # before Asio annotated them for TSan (asio 39278c4, first in 1.38.2) every handler hand-off
  # between threads is a race it cannot see and a green run means "not detected". Older Asio gets
  # its fenced blocks switched off instead (research note 4.2).
  # Asked afresh on every configure: a cached answer would outlive a switch of flavour or of Asio
  # install in an existing build directory, and the check is one small compile.
  unset(SNMPIO_ASIO_FENCES_TSAN_AWARE CACHE)
  include(CheckCXXSourceCompiles)
  include(CMakePushCheckState)
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_QUIET ON)
  set(CMAKE_REQUIRED_LIBRARIES ${SNMPIO_ASIO_TARGET})
  set(CMAKE_REQUIRED_INCLUDES ${SNMPIO_ASIO_INCLUDE_DIRS})
  check_cxx_source_compiles("
    #include <${SNMPIO_ASIO_HEADER_PREFIX}/version.hpp>
    #if ${SNMPIO_ASIO_MACRO_PREFIX}_VERSION < 103802
    #error fenced blocks not annotated for TSan
    #endif
    int main() { return 0; }" SNMPIO_ASIO_FENCES_TSAN_AWARE)
  cmake_pop_check_state()
  if(NOT SNMPIO_ASIO_FENCES_TSAN_AWARE)
    message(STATUS "snmpio: Asio predates 1.38.2; TSan build disables its fenced blocks")
    target_compile_definitions(snmpio_sanitizers INTERFACE
      ${SNMPIO_ASIO_MACRO_PREFIX}_DISABLE_FENCED_BLOCK)
  endif()
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
