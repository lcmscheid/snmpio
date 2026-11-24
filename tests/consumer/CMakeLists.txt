# A consumer of an installed snmpio that runs, where examples/ only builds: the examples need a
# Target to talk to, and this needs nothing. It checks at run time what a build alone cannot
# (#106): that the error categories are one instance each, living in the library, so a code the
# library made compares equal to snmpio::Errc in the consumer and one the consumer made classifies
# in the library -- which a shared build would break if a category were ever duplicated across the
# boundary -- and that destroying a key in consumer code reaches the library's cleanse.
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
