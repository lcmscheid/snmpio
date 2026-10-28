#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <snmpio/Password.hpp>
#include <snmpio/SecretOctets.hpp>
#include <snmpio/Usm.hpp>

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
};

template <typename T, typename U>
bool operator==(const RecordingAllocator<T>& /*a*/, const RecordingAllocator<U>& /*b*/) noexcept {
  return true;
}

using Recorded =
    std::vector<std::byte, detail::CleansingAllocator<std::byte, RecordingAllocator<std::byte>>>;
using Unwiped = std::vector<std::byte, RecordingAllocator<std::byte>>;
using RecordedString = std::basic_string<char, std::char_traits<char>, RecordingAllocator<char>>;

constexpr std::byte secret{0xA5};

bool allZero(std::span<const std::byte> bytes) {
  return std::ranges::all_of(bytes, [](std::byte b) { return b == std::byte{0}; });
}

bool contains(std::span<const std::byte> haystack, std::string_view needle) {
  return !std::ranges::search(haystack, std::as_bytes(std::span(needle))).empty();
}

class SecretOctetsTest : public ::testing::Test {
 protected:
  void SetUp() override { freed().clear(); }
};

// The seam below tests CleansingAllocator over a recording upstream; this is what ties that to the
// SecretOctets snmpio uses, whose upstream is std::allocator and whose wipe is detail::cleanse.
TEST_F(SecretOctetsTest, IsAVectorOfBytesWithTheCleansingAllocator) {
  static_assert(std::is_same_v<SecretOctets::value_type, std::byte>);
  static_assert(std::is_same_v<SecretOctets::allocator_type,
                               detail::CleansingAllocator<std::byte, std::allocator<std::byte>>>);
  static_assert(std::allocator_traits<SecretOctets::allocator_type>::is_always_equal::value);
}

TEST_F(SecretOctetsTest, TheCleanseItUsesZeroesWhatItIsGiven) {
  std::array<std::byte, 32> live{};
  live.fill(secret);
  detail::cleanse(live.data(), live.size());
  EXPECT_TRUE(allZero(live));
}

// The allocator requirements: an allocator compares equal to its own rebound copy.
TEST_F(SecretOctetsTest, AnAllocatorEqualsItsReboundCopy) {
  const detail::CleansingAllocator<std::byte> bytes;
  const detail::CleansingAllocator<char> chars(bytes);
  EXPECT_TRUE(bytes == chars);
  EXPECT_TRUE(chars == bytes);
  const Recorded::allocator_type recorded;
  using Rebound = std::allocator_traits<Recorded::allocator_type>::rebind_alloc<int>;
  const Rebound rebound(recorded);
  EXPECT_TRUE(recorded == rebound);
}

// Without this one, a recorder that saw zeros for some other reason would make the next test pass
// whatever the allocator did.
TEST_F(SecretOctetsTest, TheRecorderSeesWhatAnUnwipedBufferHeld) {
  {
    const Unwiped plain(32, secret);
  }
  ASSERT_EQ(freed().size(), 1U);
  EXPECT_EQ(freed().front(), std::vector<std::byte>(32, secret));
}

TEST_F(SecretOctetsTest, ItsBufferIsCleansedOnDestruction) {
  {
    const Recorded key(32, secret);
  }
  ASSERT_EQ(freed().size(), 1U);
  EXPECT_EQ(freed().front().size(), 32U);
  EXPECT_TRUE(allZero(freed().front()));
}

// The reason it is an allocator rather than a destructor: a vector that grows leaves its old
// buffer behind, and only the allocator sees that one go.
TEST_F(SecretOctetsTest, TheBufferAGrowingVectorLeavesBehindIsCleansedToo) {
  Recorded key;
  key.reserve(4);
  key.assign(4, secret);
  key.push_back(secret);  // past capacity: reallocates
  ASSERT_EQ(freed().size(), 1U);
  EXPECT_EQ(freed().front().size(), 4U);
  EXPECT_TRUE(allZero(freed().front()));
  EXPECT_EQ(key, Recorded(5, secret));
}

// wipeBuffer is what Password wipes its string with. A string whose storage the recorder owns
// shows what it leaves: zeros over the whole buffer, the tail a shorter value left stale included,
// by the time the buffer is handed back.
TEST_F(SecretOctetsTest, TheRecorderSeesAStringsStaleTail) {
  {
    RecordedString password(40, 'p');
    password.assign("shortpw!");  // shorter: the tail still holds the old characters
  }
  ASSERT_EQ(freed().size(), 1U);
  EXPECT_NE(std::ranges::count(freed().front(), std::byte{'p'}), 0);
}

TEST_F(SecretOctetsTest, WipingAStringZeroesItsWholeBufferStaleTailIncluded) {
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

TEST_F(SecretOctetsTest, WipingAVectorZeroesItsWholeBufferStaleTailIncluded) {
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

// A short password lives inside the Password itself, where no allocator sees it. Built in storage
// the test owns, it can be destroyed and the storage read afterwards, without reading freed memory.
TEST(PasswordTest, AShortOneIsWipedFromThePasswordsOwnStorageOnDestruction) {
  constexpr std::string_view shortOne = "shortpw!";
  alignas(Password) std::array<std::byte, sizeof(Password)> storage{};
  auto* password = new (storage.data()) Password(std::string(shortOne));
  ASSERT_EQ(password->view(), shortOne);
  ASSERT_TRUE(contains(storage, shortOne)) << "the premise: it is stored inline";
  password->~Password();
  EXPECT_FALSE(contains(storage, shortOne));
}

TEST(PasswordTest, MovingFromOneLeavesNothingBehind) {
  // What a move leaves behind is the point of this test, so it reads moved-from objects on purpose.
  // NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
  std::string caller = "shortpw!";
  Password password(std::move(caller));
  EXPECT_TRUE(caller.empty()) << "the caller's string, which a short string's move copies from";

  Password moved(std::move(password));
  EXPECT_EQ(moved.view(), "shortpw!");
  EXPECT_TRUE(password.empty());

  Password assigned = "otherpassword";
  assigned = std::move(moved);
  EXPECT_EQ(assigned.view(), "shortpw!");
  EXPECT_TRUE(moved.empty());
  // NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
}

TEST(PasswordTest, CopiesAndClearsLikeAString) {
  const Password original = "maplesyrup";
  Password copy = "something else entirely";
  copy = original;
  EXPECT_EQ(copy.view(), "maplesyrup");
  EXPECT_EQ(original.view(), "maplesyrup");
  EXPECT_EQ(copy.size(), 10U);
  copy.clear();
  EXPECT_TRUE(copy.empty());
  EXPECT_EQ(original.view(), "maplesyrup");
}

// The Credentials' secrets are Passwords and SecretOctets, so Credentials need nothing of their
// own: moving them moves every secret out and leaves none behind.
TEST(CredentialsSecrets, MovingCredentialsLeavesNoSecretInTheSource) {
  Credentials creds{"bert",       SecurityLevel::AuthPriv, AuthProtocol::Sha256,
                    "maplesyrup", PrivProtocol::Aes128,    "privatepass"};
  creds.authMasterKey = SecretOctets(32, secret);
  // NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
  const Credentials moved = std::move(creds);
  EXPECT_TRUE(creds.authPassword.empty());
  EXPECT_TRUE(creds.privPassword.empty());
  EXPECT_TRUE(!creds.authMasterKey.has_value() || creds.authMasterKey->empty());
  // NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
  EXPECT_EQ(moved.authPassword.view(), "maplesyrup");
  EXPECT_EQ(moved.privPassword.view(), "privatepass");
  EXPECT_EQ(moved.authMasterKey, SecretOctets(32, secret));
}

}  // namespace
}  // namespace snmpio
