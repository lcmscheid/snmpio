#include <gtest/gtest.h>

#include <snmpio/Error.hpp>

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
  for (int i = 0; i <= static_cast<int>(Errc::AuthFailed); ++i) {
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

}  // namespace
}  // namespace snmpio
