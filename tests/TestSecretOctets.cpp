#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include <snmpio/Usm.hpp>
#include <snmpio/detail/HeldCredentials.hpp>
#include <snmpio/detail/SecretOctets.hpp>

namespace snmpio {
namespace {

// What a buffer held at the moment it was handed back. Recorded inside deallocate, while the
// memory is still the vector's, so nothing here reads memory after it is freed.
std::vector<std::vector<std::byte>>& freed() {
  static std::vector<std::vector<std::byte>> buffers;
  return buffers;
}

// The seam: an upstream allocator that remembers what each buffer held as it is returned.
template <typename T>
struct RecordingAllocator {
  using value_type = T;  // NOLINT(readability-identifier-naming): the allocator requirements' name

  RecordingAllocator() noexcept = default;
  template <typename U>
  explicit RecordingAllocator(const RecordingAllocator<U>& /*other*/) noexcept {}

  T* allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }
  void deallocate(T* p, std::size_t n) noexcept {
    const auto* first = reinterpret_cast<const std::byte*>(p);
    freed().emplace_back(first, first + (n * sizeof(T)));
    std::allocator<T>{}.deallocate(p, n);
  }

  friend bool operator==(const RecordingAllocator& /*a*/, const RecordingAllocator& /*b*/) {
    return true;
  }
};

using Recorded =
    std::vector<std::byte, detail::CleansingAllocator<std::byte, RecordingAllocator<std::byte>>>;
using Unwiped = std::vector<std::byte, RecordingAllocator<std::byte>>;
using RecordedString = std::basic_string<char, std::char_traits<char>, RecordingAllocator<char>>;

constexpr std::byte secret{0xA5};

bool allZero(const std::vector<std::byte>& bytes) {
  return std::ranges::all_of(bytes, [](std::byte b) { return b == std::byte{0}; });
}

class SecretOctets : public ::testing::Test {
 protected:
  void SetUp() override { freed().clear(); }
};

TEST_F(SecretOctets, IsAVectorOfBytesWithTheCleansingAllocator) {
  static_assert(std::is_same_v<detail::SecretOctets::value_type, std::byte>);
  static_assert(
      std::is_same_v<detail::SecretOctets::allocator_type, detail::CleansingAllocator<std::byte>>);
}

// Without this one, a recorder that saw zeros for some other reason would make the next test pass
// whatever the allocator did.
TEST_F(SecretOctets, TheRecorderSeesWhatAnUnwipedBufferHeld) {
  {
    const Unwiped plain(32, secret);
  }
  ASSERT_EQ(freed().size(), 1U);
  EXPECT_EQ(freed().front(), std::vector<std::byte>(32, secret));
}

TEST_F(SecretOctets, ItsBufferIsCleansedOnDestruction) {
  {
    const Recorded key(32, secret);
  }
  ASSERT_EQ(freed().size(), 1U);
  EXPECT_EQ(freed().front().size(), 32U);
  EXPECT_TRUE(allZero(freed().front()));
}

// The reason it is an allocator rather than a destructor: a vector that grows leaves its old
// buffer behind, and only the allocator sees that one go.
TEST_F(SecretOctets, TheBufferAGrowingVectorLeavesBehindIsCleansedToo) {
  Recorded key;
  key.reserve(4);
  key.assign(4, secret);
  key.push_back(secret);  // past capacity: reallocates
  ASSERT_EQ(freed().size(), 1U);
  EXPECT_EQ(freed().front().size(), 4U);
  EXPECT_TRUE(allZero(freed().front()));
  EXPECT_EQ(key, Recorded(5, secret));
}

// wipeBuffer is what HeldCredentials wipes a password with. A string whose storage the recorder
// owns shows what it leaves: zeros over the whole buffer, the tail a shorter value left stale
// included, by the time the buffer is handed back.
TEST_F(SecretOctets, TheRecorderSeesAStringsStaleTail) {
  {
    RecordedString password(40, 'p');
    password.assign("shortpw!");  // shorter: the tail still holds the old characters
  }
  ASSERT_EQ(freed().size(), 1U);
  EXPECT_NE(std::ranges::count(freed().front(), std::byte{'p'}), 0);
}

TEST_F(SecretOctets, WipingAStringZeroesItsWholeBufferStaleTailIncluded) {
  {
    RecordedString password(40, 'p');
    password.assign("shortpw!");
    detail::wipeBuffer(password);
    EXPECT_TRUE(password.empty());
  }
  ASSERT_EQ(freed().size(), 1U);
  EXPECT_GT(freed().front().size(), 40U);
  EXPECT_TRUE(allZero(freed().front()));
}

TEST_F(SecretOctets, WipingAVectorZeroesItsWholeBufferStaleTailIncluded) {
  {
    Unwiped key(32, secret);
    key.resize(4);
    detail::wipeBuffer(key);
    EXPECT_TRUE(key.empty());
  }
  ASSERT_EQ(freed().size(), 1U);
  EXPECT_EQ(freed().front().size(), 32U);
  EXPECT_TRUE(allZero(freed().front()));
}

}  // namespace
}  // namespace snmpio

namespace snmpio {
namespace {

Credentials passwordCredentials() {
  return Credentials{"bert",       SecurityLevel::AuthPriv, AuthProtocol::Sha256,
                     "maplesyrup", PrivProtocol::Aes128,    "privatepass"};
}

// A std::string's storage is the standard allocator's, so no test seam reaches it; what wiping
// leaves behind is what can be checked.
TEST(HeldCredentials, WipingEmptiesThePasswordsAndMasterKeysAndKeepsTheRest) {
  Credentials creds = passwordCredentials();
  creds.authMasterKey = Octets(32, std::byte{0xA5});
  creds.privMasterKey = Octets(32, std::byte{0x5A});
  detail::wipe(creds);
  EXPECT_TRUE(creds.authPassword.empty());
  EXPECT_TRUE(creds.privPassword.empty());
  EXPECT_FALSE(creds.authMasterKey.has_value());
  EXPECT_FALSE(creds.privMasterKey.has_value());
  EXPECT_EQ(creds.userName, "bert");
  EXPECT_EQ(creds.level, SecurityLevel::AuthPriv);
  EXPECT_EQ(creds.authProtocol, AuthProtocol::Sha256);
  EXPECT_EQ(creds.privProtocol, PrivProtocol::Aes128);
}

TEST(HeldCredentials, HoldsWhatItWasGivenAndLeavesNothingInWhatItWasMovedFrom) {
  Credentials creds = passwordCredentials();
  creds.authMasterKey = Octets(32, std::byte{0xA5});
  creds.authPassword.clear();
  // What a move leaves behind is the point of this test, so it reads moved-from objects on purpose.
  // NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
  detail::HeldCredentials held(std::move(creds));
  EXPECT_EQ(held->authMasterKey, Octets(32, std::byte{0xA5}));
  EXPECT_EQ(held->privPassword, "privatepass");
  EXPECT_FALSE(creds.authMasterKey.has_value());

  const detail::HeldCredentials moved(std::move(held));
  EXPECT_EQ(moved->privPassword, "privatepass");
  EXPECT_TRUE(held->privPassword.empty());
  EXPECT_FALSE(held->authMasterKey.has_value());
  // NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
}

TEST(HeldCredentials, AssigningWipesWhatWasHeldAndMoveAssigningWipesTheSource) {
  Credentials other = passwordCredentials();
  other.authPassword = "otherpassword";
  detail::HeldCredentials held(passwordCredentials());
  const detail::HeldCredentials copy(std::move(other));

  held = copy;
  EXPECT_EQ(held->authPassword, "otherpassword");
  EXPECT_EQ(copy->authPassword, "otherpassword");

  detail::HeldCredentials source(passwordCredentials());
  held = std::move(source);
  EXPECT_EQ(held->authPassword, "maplesyrup");
  // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the point of the test
  EXPECT_TRUE(source->authPassword.empty());
}

}  // namespace
}  // namespace snmpio
