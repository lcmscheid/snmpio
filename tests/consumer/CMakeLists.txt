# A consumer of an installed snmpio that runs, where examples/ only builds: the examples need a
# Target to talk to, and this brings its own, an Agent on loopback that refuses the one request it
# gets. It checks at run time what a build alone cannot (#106): that the error categories are one
# instance each, living in the library, so a code the library made -- an Errc, and the Agent's
# error-status as the Client reports it -- compares equal to snmpio::Errc and snmpio::ErrorStatus
# in the consumer, and one the consumer made classifies in the library. A shared build would break
# that if a category were ever duplicated across the boundary. It also destroys keys in its own
# code, which compiles a call to the library's detail::cleanse into it: linking, and in a shared
# build loading, is that half's check.
#
# Standalone, like examples/, and for the same reason: it sees only what the install exports.
#
#   cmake -S tests/consumer -B build/consumer -DCMAKE_PREFIX_PATH=/opt/snmpio
#   cmake --build build/consumer && build/consumer/snmpio-consumer
cmake_minimum_required(VERSION 3.24)
project(snmpio-consumer CXX)

find_package(snmpio REQUIRED)

add_executable(snmpio-consumer Consumer.cpp)
target_link_libraries(snmpio-consumer PRIVATE snmpio::snmpio)
