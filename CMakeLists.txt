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
option(SNMPIO_HARDENING "Build our own targets with the OpenSSF compiler hardening flags" OFF)

# TSan and ASan cannot share a process, and GCC with TSan cannot build Asio warning-free: it warns
# that TSan does not model std::atomic_thread_fence, which Asio's fenced blocks use (research note
# 4.2). Clang is the one compiler the TSan build is tested with.
if(SNMPIO_TSAN AND SNMPIO_SANITIZE)
  message(FATAL_ERROR "SNMPIO_TSAN and SNMPIO_SANITIZE cannot be combined; pick one.")
endif()
if(SNMPIO_TSAN AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "SNMPIO_TSAN requires Clang; configure with -DCMAKE_CXX_COMPILER=clang++.")
endif()

# The OpenSSF set is GCC's and Clang's flags, and its linker half is GNU ld's -z options, which
# only an ELF target has: AppleClang, and GCC or Clang on macOS, Windows or Cygwin, would configure
# and then fail at link. Those are named rather than asking for ELF, because CMake documents no
# variable that says what the target's object format is. _FORTIFY_SOURCE does nothing without
# optimisation, and glibc says so with a #warning that SNMPIO_WERROR turns into a failed build; the
# OpenSSF set assumes -O2. A sanitizer replaces the very functions _FORTIFY_SOURCE wraps, so the
# two would each be checking less than they claim.
if(SNMPIO_HARDENING)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang)$" OR APPLE OR WIN32 OR CYGWIN)
    message(FATAL_ERROR
      "SNMPIO_HARDENING is the OpenSSF flag set for GCC and Clang on an ELF target.")
  endif()
  if(SNMPIO_SANITIZE OR SNMPIO_TSAN)
    message(FATAL_ERROR "SNMPIO_HARDENING cannot be combined with a sanitizer; pick one.")
  endif()
  # A multi-config generator chooses Debug at build time, past where this could refuse it.
  get_property(SNMPIO_MULTI_CONFIG GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
  if(SNMPIO_MULTI_CONFIG OR CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(FATAL_ERROR
      "SNMPIO_HARDENING needs an optimised build, chosen at configure time: _FORTIFY_SOURCE does "
      "nothing at -O0. Use a single-config generator and RelWithDebInfo, as the hardened preset "
      "does.")
  endif()
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
# The minimum versions are stated once: snmpioConfig.cmake asks a consumer's find_dependency() for
# the same ones, so an installed package never accepts a dependency version this build would have
# refused. A bare standalone Asio header tree has no version to check on either side.
set(SNMPIO_BOOST_MIN_VERSION 1.77)
set(SNMPIO_ASIO_MIN_VERSION 1.21)
set(SNMPIO_OPENSSL_MIN_VERSION 3.0)
set(SNMPIO_ASIO_FROM_PACKAGE OFF)
if(SNMP_USE_BOOST_ASIO)
  set(SNMPIO_ASIO_MACRO_PREFIX BOOST_ASIO)
  set(SNMPIO_ASIO_HEADER_PREFIX boost/asio)
  # Boost.System has been header-only since 1.69 and some distributions no longer ship a
  # boost_system component at all, so ask for the component and fall back to Boost::headers.
  find_package(Boost ${SNMPIO_BOOST_MIN_VERSION} QUIET CONFIG OPTIONAL_COMPONENTS system)
  if(NOT Boost_FOUND)
    message(FATAL_ERROR
      "Boost.Asio was not found (need Boost >= ${SNMPIO_BOOST_MIN_VERSION}, for per-operation "
      "cancellation).\n"
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
  # tree with no version to read. Neither Arch's asio nor Debian's libasio-dev ships the CMake
  # package, so the fallback is the common case, and snmpioConfig.cmake has to know which was
  # taken: only the CONFIG path leaves asio::asio in the exported interface for it to find.
  find_package(asio ${SNMPIO_ASIO_MIN_VERSION} QUIET CONFIG)
  if(asio_FOUND)
    set(SNMPIO_ASIO_TARGET asio::asio)
    set(SNMPIO_ASIO_FROM_PACKAGE ON)
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
find_package(OpenSSL ${SNMPIO_OPENSSL_MIN_VERSION} REQUIRED)

# ---------------------------------------------------------------------------
# The library
# ---------------------------------------------------------------------------
# Up to three targets compile these sources: snmpio; fuzz/'s snmpio_fuzzed, an instrumented copy
# for coverage feedback; and, in a shared build, snmpio_tested, the static copy tests/ links
# because the tests reach into what a shared snmpio hides. All take the list and
# snmpio_configure_library() from here, so a new source file, header directory or dependency is one
# edit. Absolute paths, because fuzz/ and tests/ resolve relative ones against themselves.
set(SNMPIO_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/src/BerReader.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/BerWriter.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/Client.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/Error.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/MessageIdGenerator.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/Oid.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/Password.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/Pdu.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/Usm.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/V3Message.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/Value.cpp)

# What a target compiling SNMPIO_SOURCES needs: the headers, the Asio flavour (ADR-0002), threads,
# OpenSSL and C++20. It reads SNMP_USE_BOOST_ASIO, SNMPIO_ASIO_TARGET, SNMPIO_ASIO_INCLUDE_DIRS,
# SNMPIO_GENERATED_INCLUDE_DIR and GNUInstallDirs' CMAKE_INSTALL_INCLUDEDIR from the caller's
# scope, as CMake functions do, so it is for this directory and its children (fuzz/, tests/); a
# project that add_subdirectory()s snmpio sees the function, since CMake has none private -- the
# snmpio_ prefix is its namespace -- but not the variables, and links snmpio::snmpio instead.
#
# The Asio flavour is PUBLIC: Asio types appear in public signatures, so whatever links the target
# has to be built against the same flavour. Threads are PUBLIC because Asio's headers, compiled in
# whatever includes ours, need the thread library at link time. OpenSSL is PRIVATE: no public
# header names an OpenSSL type. Consumers still need the package found, which is why
# snmpioConfig.cmake finds it -- a static archive carries its private links to the linker.
#
# The header directory is the directory of this file (CMAKE_CURRENT_FUNCTION_LIST_DIR), not the
# caller's, so fuzz/ finds the same one. The generated one, which holds <snmpio/Export.hpp>, is
# BUILD_INTERFACE only: installed, that header sits beside the others. The Asio include directory,
# when the find_path() fallback under Dependencies supplied one, is BUILD_INTERFACE only too: it is
# this machine's path, which the installed snmpio must not carry. snmpio_fuzzed and snmpio_tested
# are never installed, so for them the wrappers change nothing.
function(snmpio_configure_library target)
  target_include_directories(${target}
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_FUNCTION_LIST_DIR}/include>
      $<BUILD_INTERFACE:${SNMPIO_GENERATED_INCLUDE_DIR}>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
  # SNMPIO_EXPORT is empty in a static library, and the generated header asks for that by
  # SNMPIO_STATIC_DEFINE: without it the archive's objects, and the declarations a consumer
  # compiles, would carry default visibility, and a consumer linking the archive into a shared
  # object of its own would export our symbols from it. PUBLIC, so it travels with the target; a
  # consumer never sets it, as Boost's CMake package sets BOOST_<LIB>_DYN_LINK for its consumers in
  # the other direction.
  get_target_property(library_type ${target} TYPE)
  if(library_type STREQUAL "STATIC_LIBRARY")
    target_compile_definitions(${target} PUBLIC SNMPIO_STATIC_DEFINE)
  endif()
  target_link_libraries(${target} PUBLIC ${SNMPIO_ASIO_TARGET} Threads::Threads)
  if(SNMPIO_ASIO_INCLUDE_DIRS)
    target_include_directories(${target} SYSTEM PUBLIC
      $<BUILD_INTERFACE:${SNMPIO_ASIO_INCLUDE_DIRS}>)
  endif()
  if(SNMP_USE_BOOST_ASIO)
    target_compile_definitions(${target} PUBLIC SNMPIO_USE_BOOST_ASIO=1)
  else()
    target_compile_definitions(${target} PUBLIC ASIO_STANDALONE=1)
  endif()
  target_link_libraries(${target} PRIVATE OpenSSL::Crypto)
  target_compile_features(${target} PUBLIC cxx_std_20)
endfunction()

# Static by default, shared with -DBUILD_SHARED_LIBS=ON (#106). Either way, hidden is the default
# visibility and the public API is what SNMPIO_EXPORT marks -- the precedent is Boost's compiled
# libraries, whose BOOST_<LIB>_DECL is BOOST_SYMBOL_EXPORT or BOOST_SYMBOL_IMPORT. The macro comes
# from GenerateExportHeader as <snmpio/Export.hpp>, generated into the build tree and installed
# beside the other headers. snmpio::detail stays hidden, but for detail::cleanse (SecretOctets.hpp
# says why). The tests reach further in than any consumer, so a shared build compiles them a static
# copy of these sources, as fuzz/ always does for its own, rather than export more for them.
add_library(snmpio ${SNMPIO_SOURCES})
add_library(snmpio::snmpio ALIAS snmpio)
# Which of the two BUILD_SHARED_LIBS made snmpio, read once for tests/, which links a static copy
# when it is not STATIC_LIBRARY. snmpio_configure_library() asks the same of each target it is
# given rather than of this, since fuzz/'s and tests/' copies are static whatever snmpio is.
get_target_property(SNMPIO_LIBRARY_TYPE snmpio TYPE)

set_target_properties(snmpio PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON)

include(GenerateExportHeader)
set(SNMPIO_GENERATED_INCLUDE_DIR "${PROJECT_BINARY_DIR}/include")
generate_export_header(snmpio
  EXPORT_FILE_NAME "${SNMPIO_GENERATED_INCLUDE_DIR}/snmpio/Export.hpp"
  INCLUDE_GUARD_NAME SNMPIO_EXPORT_HPP)
snmpio_configure_library(snmpio)

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

# The OpenSSF Compiler Options Hardening Guide's TL;DR set, its x86_64 row and its production row
# (research note 5.1; #46), behind SNMPIO_HARDENING. Opt-in and PRIVATE to our own targets for the
# reason the standard-library macros are PRIVATE, only more so: most of these are the consumer's
# build's business, and some -- -ftrivial-auto-var-init, -fno-strict-aliasing -- change what code
# compiles to. Lists, not an INTERFACE target, for the same export reason. Empty when the option is
# off, so applying them is unconditional.
#
# The set less what is already here: -Wall and -Wconversion are snmpio_warnings', and the two
# standard-library macros are SNMPIO_STDLIB_HARDENING, on in every build. -O2 is RelWithDebInfo's,
# and the configure above refuses Debug. -U first, as the guide has it, so a toolchain that
# defines _FORTIFY_SOURCE itself, as Ubuntu's GCC does, is overridden rather than redefined.
#
# The link options matter wherever we link: the test binaries, and snmpio itself in a shared build.
# A static archive is not linked, and CMake applies LINK_OPTIONS to the link step alone.
set(SNMPIO_HARDENING_COMPILE_OPTIONS)
set(SNMPIO_HARDENING_LINK_OPTIONS)
if(SNMPIO_HARDENING)
  set(SNMPIO_HARDENING_COMPILE_OPTIONS
    -Wformat -Wformat=2 -Wimplicit-fallthrough -Werror=format-security
    -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
    -fstrict-flex-arrays=3 -fstack-clash-protection -fstack-protector-strong
    # production
    -fno-delete-null-pointer-checks -fno-strict-overflow -fno-strict-aliasing
    -ftrivial-auto-var-init=zero)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
    list(APPEND SNMPIO_HARDENING_COMPILE_OPTIONS -fcf-protection=full)
  endif()
  set(SNMPIO_HARDENING_LINK_OPTIONS
    LINKER:-z,nodlopen LINKER:-z,noexecstack LINKER:-z,relro LINKER:-z,now
    LINKER:--as-needed LINKER:--no-copy-dt-needed-entries)
endif()

# Both kinds of hardening, PRIVATE, on one of our own targets: snmpio here, the test binaries in
# tests/. One call per target, so a new target cannot take one kind and miss the other. fuzz/'s
# instrumented copy sets the standard-library macros itself, beside its sanitizer's, and refuses
# SNMPIO_HARDENING by way of the sanitizer check above.
function(snmpio_harden target)
  target_compile_definitions(${target} PRIVATE ${SNMPIO_STDLIB_HARDENING})
  target_compile_options(${target} PRIVATE ${SNMPIO_HARDENING_COMPILE_OPTIONS})
  target_link_options(${target} PRIVATE ${SNMPIO_HARDENING_LINK_OPTIONS})
endfunction()
snmpio_harden(snmpio)

# Both lists as they reach a command line, one flag per line, for CI to check against: that every
# flag reached each of our compile and link lines (.github/scripts/hardening-reached.sh), and that
# none reached a consumer (hardening-stays-ours.sh). CI reads them rather than naming the flags
# itself, so this file is the only place the set is written down. The link options are written in
# GCC's -Wl, spelling; CMake gives Clang -Xlinker instead, and the scripts read both. Only with the
# option on, and removed with it off, so a build reconfigured without it has no stale lists.
if(SNMPIO_HARDENING)
  list(TRANSFORM SNMPIO_STDLIB_HARDENING PREPEND "-D" OUTPUT_VARIABLE SNMPIO_COMPILE_FLAG_LIST)
  list(APPEND SNMPIO_COMPILE_FLAG_LIST ${SNMPIO_HARDENING_COMPILE_OPTIONS})
  list(JOIN SNMPIO_COMPILE_FLAG_LIST "\n" SNMPIO_COMPILE_FLAG_LINES)
  file(WRITE "${PROJECT_BINARY_DIR}/hardening/compile-flags.txt" "${SNMPIO_COMPILE_FLAG_LINES}\n")
  list(TRANSFORM SNMPIO_HARDENING_LINK_OPTIONS REPLACE "^LINKER:" "-Wl,"
    OUTPUT_VARIABLE SNMPIO_LINK_FLAG_LIST)
  list(JOIN SNMPIO_LINK_FLAG_LIST "\n" SNMPIO_LINK_FLAG_LINES)
  file(WRITE "${PROJECT_BINARY_DIR}/hardening/link-flags.txt" "${SNMPIO_LINK_FLAG_LINES}\n")
else()
  file(REMOVE_RECURSE "${PROJECT_BINARY_DIR}/hardening")
endif()

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

# detail/*View.hpp -- CacheView, DeriverView, MessageIdView, OutstandingView -- are the tests'
# windows onto a Client, not API: Client.hpp only forward-declares them, so an installed snmpio is
# whole without them. A pattern rather than a list, so that the next view is left out too.
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  PATTERN "*View.hpp" EXCLUDE)
install(FILES "${SNMPIO_GENERATED_INCLUDE_DIR}/snmpio/Export.hpp"
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/snmpio)

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
