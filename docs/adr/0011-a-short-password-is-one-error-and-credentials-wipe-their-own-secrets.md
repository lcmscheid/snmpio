# A short password is one error, and Credentials wipe their own secrets

RFC 3414 section 11.2 says a password MUST be at least 8 characters. snmpio refuses a shorter one
with `Errc::PasswordTooShort`, classified `Configuration`, before anything is sent. #38 asked for
that as "a new ErrorCode". Three choices follow from it, and none is what a reader would assume.

**`PasswordTooShort` replaced `EmptyPassword` rather than sitting beside it.** The old code meant
"password-to-key cannot expand an empty password". That is now one of the lengths the rule
refuses, not a separate fault. With two codes, a caller who wants to say "fix your password" would
have to check for both, and snmpio would have to decide which one a zero-length password gets. One
rule, one code: `Error.hpp`'s rationale for `ArgumentOutOfRange` already argues this way. The
enumerator keeps its slot, so the integer is unchanged and only its meaning widens.

**`passwordToKey` refuses the same lengths the Client does.** Otherwise a Master Key derived ahead
of time, the way the README recommends, would escape the rule that the same password given directly
would hit. The rule belongs to the password, not to the path it takes to the Client.

**A short password is refused wherever one is given, even where the Security Level does not use
it.** A 5-character privacy password at `authNoPriv` is a mistake in the Credentials. It would
surface the moment someone raised the level, far from where it was made. This is the rule S3
already applies to a wrong-width Master Key the level does not use. An *empty* password where the
level does not need one is no password at all, and passes.

**The Credentials' secrets are public types that wipe themselves.** The passwords are
`snmpio::Password` and the Master Keys `snmpio::SecretOctets`, and the key derivations return
`SecretOctets`. The first cut kept `std::string` and `Octets` in the public type and wiped only the
Client's own copies, through an internal holder. That left the caller's Credentials, and every key
the public derivations handed out, outside threat model S5, and #38 asked for every stored password
and key. With the fields themselves wiping, the holder is gone and a `Credentials` needs nothing of
its own: its implicit destructor and moves do the work, in the caller's keeping and in each
coroutine frame. `Password` converts implicitly from `std::string` and string literals, so a braced
Credentials initialiser still reads as it did. It does not convert back implicitly, because that
would make an unwiped copy.

## Consequences

**A source break, pre-1.0.** Code that names `Errc::EmptyPassword` no longer compiles. Code that
treats `authPassword` as a `std::string` (`+=`, passing it as a `string_view`) now goes through
`view()`. Code that stores a derived key in `Octets` now gets `SecretOctets`, which does not convert
implicitly. Each break is at compile time, none at run time, and each is the point: a silent
conversion would be exactly where a secret escapes into storage that does not wipe.

**Two test vectors went.** The 1- and 7-character rows of `PasswordToKey`'s awkward-length
table could no longer be derived. They were replaced with 8-, 9- and 11-character rows computed with
Python's hashlib, which still exercise the expansion at lengths that divide nothing.

**Stricter than before.** Credentials that worked at `authNoPriv` with a short, unused privacy
password now fail. That is deliberate, for the reason above.
