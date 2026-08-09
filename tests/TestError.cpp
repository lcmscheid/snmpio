#include <gtest/gtest.h>

#include <string>
#include <system_error>

#include <snmpio/Error.hpp>
#include <snmpio/Pdu.hpp>

namespace snmpio {
namespace {

TEST(Error, SuccessIsFalsey) {
  const net::ErrorCode ok = make_error_code(Errc::Ok);
  EXPECT_FALSE(ok);
  EXPECT_TRUE(make_error_code(Errc::Truncated));
}

TEST(Error, ComparesAgainstTheEnumDirectly) {
  // This is what the is_error_code_enum registration buys, and it has to keep working under both
  // Asio flavours (ADR-0002) because callers will write it.
  const net::ErrorCode ec = make_error_code(Errc::OidTooLong);
  EXPECT_EQ(ec, Errc::OidTooLong);
  EXPECT_NE(ec, Errc::OidEmpty);
}

TEST(Error, EveryCodeHasAMessage) {
  for (int i = 0; i <= static_cast<int>(Errc::UnexpectedReport); ++i) {
    const net::ErrorCode ec = make_error_code(static_cast<Errc>(i));
    const std::string message = ec.message();
    EXPECT_FALSE(message.empty()) << i;
    EXPECT_EQ(message.rfind("unknown snmpio error", 0), std::string::npos)
        << "code " << i << " fell through the switch";
  }
}

TEST(Error, CategoryIsASingleton) {
  EXPECT_EQ(&errorCategory(), &errorCategory());
  EXPECT_STREQ(errorCategory().name(), "snmpio");
}

// A code the category has a message for is a code this library defines. Driving the coverage
// sweep off that rather than off a hand-written last-enumerator bound is what makes it fail when
// someone appends an enumerator: append it after UnexpectedReport and an `i <= UnexpectedReport`
// loop would never reach it. The cost is a coupling to the two "unknown ..." fallthrough strings
// in Error.cpp and Pdu.cpp.
//
// It catches an enumerator that was given a message but no classification. The other half -- an
// enumerator given neither -- is unreachable from outside the library and is caught at compile
// time instead: neither switch has a default, so -Werror=switch rejects the build.
constexpr int scannedCodes = 256;

template <typename Enum>
void expectEveryDefinedCodeIsClassified(const char* label) {
  for (int i = 0; i < scannedCodes; ++i) {
    const net::ErrorCode ec = make_error_code(static_cast<Enum>(i));
    const ErrorClass cls = classify(ec);
    if (ec.message().starts_with("unknown ")) {
      EXPECT_EQ(cls, ErrorClass::Unclassified)
          << label << " " << i << " classifies but has no message";
    } else {
      EXPECT_NE(cls, ErrorClass::Unclassified) << label << " " << i << " (" << ec.message() << ")";
    }
  }
}

TEST(ErrorClassification, EveryErrcIsClassified) {
  expectEveryDefinedCodeIsClassified<Errc>("Errc");
}

TEST(ErrorClassification, EveryErrorStatusIsClassified) {
  expectEveryDefinedCodeIsClassified<ErrorStatus>("ErrorStatus");
}

TEST(ErrorClassification, SuccessIsOkInEveryCategory) {
  EXPECT_EQ(classify(net::ErrorCode{}), ErrorClass::Ok);
  EXPECT_EQ(classify(make_error_code(Errc::Ok)), ErrorClass::Ok);
  EXPECT_EQ(classify(make_error_code(ErrorStatus::NoError)), ErrorClass::Ok);
}

TEST(ErrorClassification, SilenceIsWorthRetryingAndAWrongPasswordIsNot) {
  // The distinction the whole classification exists for.
  EXPECT_EQ(classify(make_error_code(Errc::Timeout)), ErrorClass::Retriable);
  EXPECT_EQ(classify(make_error_code(Errc::AuthFailed)), ErrorClass::Configuration);
  EXPECT_EQ(classify(make_error_code(Errc::DecryptionFailed)), ErrorClass::Configuration);
  EXPECT_EQ(classify(make_error_code(Errc::UnknownUserName)), ErrorClass::Configuration);
}

TEST(ErrorClassification, MalformedRepliesAndOurOwnStopAreFatal) {
  EXPECT_EQ(classify(make_error_code(Errc::Truncated)), ErrorClass::Fatal);
  EXPECT_EQ(classify(make_error_code(Errc::NonIncreasingOid)), ErrorClass::Fatal);
  EXPECT_EQ(classify(make_error_code(Errc::ClientStopped)), ErrorClass::Fatal);
}

TEST(ErrorClassification, TheAgentsOwnErrorStatusIsClassified) {
  EXPECT_EQ(classify(make_error_code(ErrorStatus::AuthorizationError)), ErrorClass::Configuration);
  EXPECT_EQ(classify(make_error_code(ErrorStatus::TooBig)), ErrorClass::Configuration);
  EXPECT_EQ(classify(make_error_code(ErrorStatus::ResourceUnavailable)), ErrorClass::Retriable);
  EXPECT_EQ(classify(make_error_code(ErrorStatus::CommitFailed)), ErrorClass::Fatal);
}

TEST(ErrorClassification, SystemCategoryFaultsAreClassifiedToo) {
  const auto system = [](std::errc e) {
    return net::ErrorCode(static_cast<int>(e), net::systemCategory());
  };
  EXPECT_EQ(classify(system(std::errc::host_unreachable)), ErrorClass::Retriable);
  EXPECT_EQ(classify(system(std::errc::network_down)), ErrorClass::Retriable);
  // Cancellation: the caller already decided, so there is nothing to retry.
  EXPECT_EQ(classify(system(std::errc::operation_canceled)), ErrorClass::Fatal);
  EXPECT_EQ(classify(system(std::errc::permission_denied)), ErrorClass::Fatal);
}

// Boost.System's error_category has a protected non-virtual destructor on purpose -- categories
// are singletons, never deleted through a base pointer -- so deriving one trips a warning that is
// a false positive here, exactly as it is in Error.cpp.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#endif

class ForeignCategory final : public net::ErrorCategory {
 public:
  const char* name() const noexcept override { return "not-ours"; }
  std::string message(int ev) const override { return "foreign " + std::to_string(ev); }
};

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

TEST(ErrorClassification, AFourthCategoryIsUnclassifiedRatherThanGuessed) {
  // The honest answer for a category we cannot interpret. Guessing Fatal here would be a retry
  // policy deciding on evidence it does not have.
  static const ForeignCategory foreign;
  EXPECT_EQ(classify(net::ErrorCode(1, foreign)), ErrorClass::Unclassified);
}

}  // namespace
}  // namespace snmpio
