// The Asio shim (ADR-0002).
//
// The library compiles against either Boost.Asio or standalone Asio, selected by the
// SNMP_USE_BOOST_ASIO CMake option. That choice leaks into every public signature, so no public
// header may name the Asio namespace or the error_code type directly -- everything goes through
// the aliases below.
#ifndef SNMPIO_DETAIL_ASIO_HPP
#define SNMPIO_DETAIL_ASIO_HPP

#include <type_traits>

#if defined(SNMPIO_USE_BOOST_ASIO)
#include <boost/system/error_category.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#else
#include <system_error>
#endif

namespace snmpio::net {

#if defined(SNMPIO_USE_BOOST_ASIO)
using ErrorCode = ::boost::system::error_code;
using ErrorCategory = ::boost::system::error_category;
using SystemError = ::boost::system::system_error;
inline const ErrorCategory& systemCategory() noexcept {
  return ::boost::system::system_category();
}
inline const ErrorCategory& genericCategory() noexcept {
  return ::boost::system::generic_category();
}
#else
using ErrorCode = ::std::error_code;
using ErrorCategory = ::std::error_category;
using SystemError = ::std::system_error;
inline const ErrorCategory& systemCategory() noexcept {
  return ::std::system_category();
}
inline const ErrorCategory& genericCategory() noexcept {
  return ::std::generic_category();
}
#endif

}  // namespace snmpio::net

// Enrols an enum as an error-code enum with whichever error framework is in play. Used by
// Error.hpp; kept here so the #if lives in exactly one file. A macro because it opens a namespace
// and declares a specialisation -- there is no function or template that can do that.
// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#if defined(SNMPIO_USE_BOOST_ASIO)
#define SNMPIO_REGISTER_ERROR_CODE_ENUM(Enum)            \
  namespace boost::system {                              \
  template <>                                            \
  struct is_error_code_enum<Enum> : ::std::true_type {}; \
  }
#else
#define SNMPIO_REGISTER_ERROR_CODE_ENUM(Enum)            \
  namespace std {                                        \
  template <>                                            \
  struct is_error_code_enum<Enum> : ::std::true_type {}; \
  }
#endif
// NOLINTEND(cppcoreguidelines-macro-usage)

#endif  // SNMPIO_DETAIL_ASIO_HPP
