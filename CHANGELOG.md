# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of SLIP-0039 Shamir's Secret Sharing
- Complete SLIP-0039 specification compliance
- BIP32 master key generation from recovered secrets
- Command-line interface for all operations
- Comprehensive test suite with official test vectors
- Cross-platform support (Windows, Linux, macOS)
- Passphrase support for enhanced security
- Memory-safe handling of cryptographic material

### Core Library Features
- `Slip39ShareGeneration` - Create mnemonic shares from secrets
- `Slip39ShareCombination` - Recover secrets from shares
- `Slip39ShareParser` - Parse and validate mnemonic strings
- `Bip32MasterKey` - Generate BIP32 extended private keys
- `GaloisField256` - Galois Field arithmetic operations
- `PolynomialInterpolation` - Shamir's secret sharing mathematics
- `Rs1024Checksum` - RS1024 error detection checksums
- `Slip39Encryption` - PBKDF2 key derivation and AES encryption
- `Slip39Passphrase` - Passphrase normalization and handling
- `Wordlist` - SLIP-0039 wordlist management

### CLI Commands
- `split` - Split secrets into mnemonic shares
- `combine` - Combine shares to recover secrets
- `info` - Display share information
- `validate` - Validate individual shares
- `generate` - Generate BIP32 master keys

### Testing
- 100% SLIP-0039 test vector compliance
- Comprehensive unit tests for all components
- CLI integration tests
- Error condition and edge case testing
- Performance and security testing
- `Slip39ShareCombination.ValidateChecksums` now encodes shares through
  `Slip39ShareParser.ShareToIndices` instead of a ~60-line private copy of it. Two
  hand-maintained copies of the share bit layout is exactly the shape of the `ToHex` /
  `ParseFromHex` defect, and a test reaching into the private copy by reflection had made the
  duplicate harder to delete than to keep.
- `ValidateChecksums_ValidShares_ShouldNotThrow` now validates the shares it generates. It used
  to build them, discard them, and call `ValidateChecksums` on an empty list — which passes
  without executing its loop body. It was parked behind a comment claiming share generation
  "doesn't yet calculate proper checksums", which had long since stopped being true. A
  companion test covering a corrupted share was added, since a passing-shares test alone would
  still pass if the method accepted everything.
- New `Slip39.Console.Tests` project covering the command line interface, which previously had
  no tests at all. The tests drive the CLI in process and assert on the exit code and on which
  stream each message goes to, not only on its wording — every CLI defect fixed in this
  release printed a plausible message and still exited 0.
- Removed `Bip32DebugTests`: four `[Fact]` methods, 190 lines, no assertion of any kind. They
  were investigation scaffolding — "Debug tests to investigate BIP32 master key generation
  differences" — that printed 39 lines to the console and could not fail. One of them wrapped
  its body in `if (result.IsSuccess)`, so it passed just as quietly when the combine failed.
  They counted as four green tests in every report this project has produced. Nothing was lost:
  `Slip39ReferenceVectorTests.ValidMnemonics_ShouldGenerateCorrectMasterKey` already asserts
  mnemonic-to-`xprv` against every valid reference vector, which is what the largest of the four
  was printing for one of them.

### Documentation
- Complete API documentation
- Usage examples and tutorials
- Security best practices
- Installation and setup guides

### Fixed
- **Interoperability**: no passphrase now means the empty string, as SLIP-0039 requires ("If no
  passphrase is provided, an empty string SHALL be used as the passphrase"). This library
  substituted `"TREZOR"` — the passphrase the specification's *test vectors* use — so every share
  it produced without an explicit passphrase was encrypted with a passphrase no other
  implementation would guess. The failure mode is the worst available: SLIP-0039 deliberately
  provides no way to verify a passphrase, so nothing errors. Another implementation decrypts to a
  different secret and reports success; for a BIP-32 seed that is an empty wallet rather than an
  error message. Verified in both directions against Trezor's `shamir-mnemonic` 0.3.0 across
  seven configurations. **Shares created with an earlier version of this tool and no explicit
  passphrase need `--passphrase TREZOR` to recover.**
- **Interoperability**: `slip39 combine --bip32` reads the recovered secret as a BIP-32 master
  seed at every length, which is what SLIP-0039 requires a backup to contain. It used to assume
  that any 64-byte secret came from `split-xpriv` and reassemble it as a private key and chain
  code — so a genuine 512-bit BIP-32 seed, a length the specification explicitly supports,
  produced the wrong wallet under a confident label. Nothing in the recovered bytes distinguishes
  the two, so the choice is now the caller's: `--reconstruct-xpriv` selects the `split-xpriv`
  reading, and a 64-byte secret is reported with a note naming the other interpretation.
- `slip39 split-xpriv` says what it produces. Its shares are valid SLIP-0039 and any
  implementation recovers the same 64 bytes, but the specification requires a BIP-32 backup to
  contain the master *seed*, and an xprv does not contain it — what is split is the private key
  and chain code. Another wallet restoring those shares derives a different wallet without
  reporting an error. The seed cannot be recovered from an xprv, so the command cannot be made
  conformant; it now warns, and points at `slip39 split` for a portable backup.
- **CLI**: `split-xpriv` no longer prints the private key and chain code by default. Both are
  now behind `--show-secret`, alongside the combined secret. A tool for keeping key material
  off screens and out of logs was writing the whole wallet to stdout on every invocation.
- **CLI**: `split-xpriv` rejects anything that is not a mainnet extended *private* key. An
  `xpub` decodes to the same 78 bytes, so it previously passed with only a warning; the
  command then labelled part of the public key "Private Key" and split it into shares,
  producing a confident-looking backup that cannot restore a wallet.
- **CLI**: every command now returns a non-zero exit code when it fails, and writes its error
  messages to stderr instead of stdout. Failures previously exited 0, so a backup script had
  no way to tell a successful split from a rejected one.
- **CLI**: an unrecognised option is now an error. `split --treshold 5 --shares 7` silently
  ignored the misspelled flag and produced a 2-of-7 split — weaker parameters than the user
  asked for, with nothing to indicate anything had been dropped.
- **CLI**: `info` accepts its options before the mnemonic, as its own help documents.
  `slip39 info --format json "<share>"` used to take `--format` as the share and fail.
- **CLI**: command and format names are matched with `ToLowerInvariant`. Under a Turkish
  locale `INFO` lowercased to `ınfo` and no command matched.
- **CLI**: the recovered master secret, the generated secret and the decoded BIP32 key
  material are zeroed before each command returns, honouring the ownership contract the
  library documents.
- `GaloisField256.Power` no longer throws on large exponents. It computed
  `log(base) * exponent` in `int` before reducing modulo 255; for a base with a large discrete
  logarithm the product overflowed, `%` kept the sign, and the negative index threw
  `IndexOutOfRangeException` — `Power(246, 8455448)` for instance. The exponent is now reduced
  first, which is exact because the multiplicative group of GF(256) has order 255.
- `Slip39ShareParser.ParseFromMnemonic` splits on any whitespace, not only `' '`. A share
  pasted out of a file, a printed backup or a multi-line message failed with "Expected at least
  20 words, got 1" — an error about the share, for what was only a line break.
- `Slip39Share.ToHex()` and `Slip39ShareParser.ParseFromHex()` no longer disagree on the
  bit layout. `ToHex()` appended the share value padding while the parser expected it
  before the value, so a share exported as hex could not be read back — `ParseFromHex()`
  rejected it with "Invalid mnemonic checksum". `ToHex()` now derives its bit stream from
  the same `ShareToIndices` used by `ToMnemonic()`, and `ParseFromHex()` discards the
  trailing byte-alignment slack before parsing.
- **CI**: the Security Scan job can upload its CodeQL results. `ci.yml` declared no
  `permissions` at all, so the job ran with the repository's default token, which may not write
  the repository's code scanning alerts. The analysis itself always succeeded — it scans every
  C# file and produces its SARIF — and the job then died on the upload with "Resource not
  accessible by integration". Every push to `main` had failed this way since the workflow was
  written in June 2025, and nobody saw it: on a pull request the same upload succeeds, so the
  checks that gate a merge were green throughout while the scan on the default branch had never
  once completed. The repository's code scanning state was therefore never written from `main`;
  every alert acted on in this release came from a pull request. `permissions` is declared per
  job rather than as a workflow-level default, so that `build-artifacts` keeps the
  `contents: write` its release upload needs; both jobs now state their own scope.
- **CI**: the vulnerable-package scan can fail the build. `dotnet list package --vulnerable`
  prints what it finds and exits 0 whether or not it found anything, so the step named "Security
  scan" was informational only: a vulnerable transitive dependency would have been printed into
  a green log. The step now reads its own report and exits non-zero on a hit.
- **CI**: the SonarCloud scan can run. Its `if: env.SONAR_TOKEN != ''` guard tested a variable
  the same step defined in its own `env:`, which is not in scope for that step's `if:` — so the
  condition compared `''` to `''` and skipped the scan on every run since the workflow was
  written. `SONAR_TOKEN` is now a job-level env, which the condition can see. The scan has
  therefore never executed; the first run that finds a configured token will be its first real
  test, and may need follow-up.
- **CI**: release assets are uploaded with `gh release upload` instead of
  `actions/upload-release-asset@v1`, which GitHub archived in 2021. `build-artifacts` only runs
  on a `release` event, so this path has never executed and its failure would have been
  discovered during a release. Four near-identical upload steps collapse into one, and
  `--clobber` makes a re-run after a partial failure idempotent.
- **CI**: the NuGet API key is passed to `dotnet nuget push` through the environment rather than
  interpolated into the command line, where it would be readable by anything able to list
  processes on the runner.
- Test vectors are located through `AppContext.BaseDirectory` rather than
  `Directory.GetCurrentDirectory()` in `Slip39ReferenceVectorTests` and
  `TestVectorValidationTests`. The csproj copies `vectors.json` next to the test assembly; the
  working directory belongs to the test runner and merely happens to coincide today. The
  interop vectors were already loaded this way, so the two spellings now agree.

### Changed
- `Slip39ShareGeneration.CombineShares` is now `[Obsolete]` and forwards to
  `Slip39ShareCombination.CombineShares`. It had been a second, independent implementation of
  the same algorithm, and the two had drifted: it never received the key-material zeroing,
  iterated groups in `Dictionary` order rather than by group index, and threw on a null
  passphrase instead of applying the `"TREZOR"` default. Two public entry points for one
  operation, differing in their security properties, is a trap — whichever a caller reaches for
  first is the one they get. Note the forwarding also makes it strict about the member
  threshold, in line with the change below.
- **Breaking**: removed `Rs1024Checksum.BytesToWords`, `WordsToBytes` and `BytesToWordsExact`.
  They had no callers outside the test suite, and despite sitting on the checksum class they do
  not produce the SLIP-0039 share layout: they pad the final 10-bit word on the right, where the
  specification left-pads the share value. For a 128-bit value the two disagree completely
  (`[0,274,140,836,…]` against `[0,68,547,209,…]`). A helper that looks canonical, is reachable
  from the checksum type, and silently encodes something else is the same trap that produced the
  `ToHex`/`ParseFromHex` defect.
- Removed the private, `[Obsolete]` `Slip39ShareGeneration.ValidateCombineShares` and the unused
  `Slip39ShareCombination.PackBits`. A private method marked obsolete is unreachable by
  definition.
- **Breaking**: `Slip39ShareCombination.CombineShares` now requires exactly the member threshold
  from each group, as SLIP-0039 requires ("their count *Mᵢ* MUST be equal to *Tᵢ*"). Passing
  more was previously accepted, and the surplus was discarded by `RecoverSecret` without ever
  being examined: two good shares plus one that had rotted recovered the correct secret and
  reported success, never mentioning the bad one. Whether corruption was noticed came down to
  where in the list the share happened to sit — first, and the digest check caught it; last,
  and nothing was said. The group-level equivalent of this rule (`GM == GT`) was already
  enforced, so the two levels now behave alike.
- The `slip39 combine` CLI still accepts more shares than the threshold. It now verifies the
  surplus against the rest before trimming the set for recovery, and by default refuses to
  recover from a set that contradicts itself, so nothing is silently dropped.
- `Bip32MasterKey.GenerateMasterKey` and `Slip39.GenerateMasterKey` are `[Obsolete]` in their
  two-argument form and gained a one-argument overload. The passphrase argument was never used
  and cannot be: BIP-32 derivation is `HMAC-SHA512("Bitcoin seed", seed)` and takes no
  passphrase. In SLIP-0039 the passphrase is consumed earlier, decrypting the master secret. A
  parameter that looks like it changes the result and does not is a trap — and three tests were
  asserting that different passphrases produced the same key, one of them attributing it to
  Unicode normalisation rather than to the argument being ignored.
- **Breaking**: `Slip39ShareParser.ParseFromJson` validates what it reads, like the other two
  parsers. `ParseFromMnemonic` and `ParseFromHex` both route through `ParseFromBits`, which
  checks the field ranges and the RS1024 checksum; `ParseFromJson` returned whatever
  `JsonSerializer.Deserialize` produced. A share round-tripped through JSON was therefore
  trusted without any of the integrity checking the same share received as a mnemonic — a
  checksum could be replaced with any number at all, and an identifier of 65535 was accepted,
  after which `ShareToIndices` masked it down to 15 bits and produced a mnemonic that was wrong
  rather than rejected. Shares hand-built or patched as JSON now have to carry a correct
  checksum.
- **Breaking**: `Slip39Share` can only be built through its validating constructor, and its
  fields are `init`-only. The parameterless constructor and public setters sat beside the
  validating constructor as an equally valid path, so `new Slip39Share { Identifier = 65535,
  IterationExponent = 200 }` produced a share the constructor would have rejected — and
  `System.Text.Json` took exactly that path, which is why the JSON parser had no validation to
  bypass in the first place. `TotalIterations` returning 2,560,000 for an exponent of 200
  (`1 << 200` shifts by `200 & 31`) was a symptom: the class documented field ranges it did not
  maintain. The constructor now carries `[JsonConstructor]`, so deserialising goes through the
  same checks as every other caller.
- **Breaking**: `Wordlist.Words` returns `IReadOnlyList<string>` instead of the live internal
  `string[]`. It handed out the array itself, so `Wordlist.Words[0] = "PWNED"` from anywhere in
  the process permanently changed how every mnemonic encodes and decodes — for `GetWord`,
  `GetIndex` and every caller of both. Callers that stored it in a `string[]` will not compile;
  indexing and enumeration are unchanged.
- **Breaking**: the wordlist is loaded from the embedded resource only, and is verified when it
  is loaded. The filesystem fallback meant a `wordlist.txt` dropped next to the DLL silently
  became the wordlist, with nothing checking that it was the right one — the only test was a
  count of 1024, and the word-to-index map overwrote duplicates in silence, so a list with a
  repeated word passed while `GetIndex` resolved to the last occurrence. The resource is
  embedded by the project file, so its absence is a build failure rather than a runtime
  condition to paper over. What is loaded is now checked against the criteria the specification
  states — 1024 entries, sorted, 4 to 8 letters, unique 4-letter prefixes — and then against the
  SHA-256 of the wordlist itself, since being well formed does not make it the right list.
- Removed the `index|word` branch of the wordlist reader. Its two halves disagreed on whether
  `index` was 0- or 1-based, so the format it appeared to support could not load: the resulting
  count tripped the 1024 check. The shipped wordlist is one word per line and never took that
  path.
- **Breaking**: `Slip39Passphrase.EstimatePassphraseEntropy` is `[Obsolete]` and forwards to
  `MaximumPassphraseEntropyBits`, which is what the number always was: `length × log2(alphabet
  size)`, an upper bound assuming every character was chosen uniformly at random. It cannot see
  a dictionary word or a keyboard walk, so `Password1!` scored ~65 bits — the same as ten random
  characters from the same alphabet. In a library people use to decide how to protect a wallet,
  a name promising an entropy estimate over a number that rates a weak passphrase as strong is
  worse than no API at all.
- `slip39 combine --ignore-invalid-shares` recovers from the shares that do agree when some do
  not, provided a quorum survives in every group. Someone recovering under pressure should not
  be blocked by one share mis-transcribed years ago when the rest are sufficient; the shares
  that were excluded are still reported, and the recovered secret is verified against its
  SLIP-0039 digest either way.
- **CI**: the test suite runs once per platform instead of four times per run. The `code-quality`
  job re-ran the whole suite after the `test` job had already run it on Linux, macOS and Windows,
  then rendered an HTML coverage report into a directory nothing read or uploaded. The suite
  takes roughly 26 minutes, most of it in one 15-exponent PBKDF2 case, so this was a fourth full
  run whose only output was discarded. Coverage now comes from the `test` job alone, which
  gained the `coverlet.runsettings` the duplicate run was using so its exclusions survive the
  removal.

### Added
- Interoperability test vectors generated by Trezor's `shamir-mnemonic`, four of them with no
  passphrase. The specification's own vectors all use `"TREZOR"`, so nothing in the suite
  exercised the no-passphrase path — which is exactly where this library diverged. A round trip
  through this library alone could not have caught it: both sides would be wrong in the same way.
- `Slip39Passphrase.IsPortablePassphrase` reports whether a passphrase is printable ASCII, which
  the specification requires "in order to achieve the best interoperability among various
  operating systems and wallet implementations". The CLI warns when generating shares with a
  passphrase outside that range, and never when recovering: refusing one at recovery time would
  make an existing backup unreadable.
- `Slip39ShareCombination.VerifyShares` checks every share you hold against the others in its
  group, rather than the threshold-many that recovery consumes. It answers "is my backup still
  intact?", which recovery alone cannot. No passphrase is needed and no secret is returned: the
  shares of a group are points on one polynomial, so any *T* of them fix it and every remaining
  share must land on it. The report marks each share `Consistent`, `Inconsistent` or
  `Unverifiable`, the last for groups holding fewer shares than their threshold.

  The reference subset is searched for rather than assumed. Any *T* shares agree with
  themselves, so agreement cannot distinguish a sound subset from one fitted through corrupt
  points — only the SLIP-0039 digest can. Taking the first *T* would therefore fit a polynomial
  through bad data whenever a bad share came early, and flag the good shares instead. A corrupt
  share is now named wherever it appears in the list. Where the supplied shares split into two
  sets that each reconstruct a *different* secret, neither is chosen and the group is reported
  as not coming from a single backup.
- `slip39 validate` now cross-checks the shares it is given, not just each share's own
  checksum. A valid checksum proves a mnemonic was transcribed without a typo; it says nothing
  about whether the shares belong together, which is what someone testing an old backup wants
  to know.
- **Breaking**: the hexadecimal share format produced by `Slip39Share.ToHex()` and the CLI
  `--format hex` has changed to the canonical SLIP-0039 bit layout. Hex strings written by
  earlier versions encode a different bit order and will not parse; re-export affected
  shares from their mnemonic form. Mnemonic and JSON formats are unaffected.
- The share-length parser now rejects padding above 8 bits, matching the SLIP-0039 wording
  ("MUST NOT exceed 8 bits") instead of the equivalent but less obvious 10-bit bound.
- A mnemonic whose share-value padding bits are not zero now reports "Invalid mnemonic
  padding" instead of "Invalid mnemonic checksum". Such mnemonics were already rejected, so
  this changes the diagnostic rather than the verdict — but the old message sent anyone
  debugging a hand-copied share looking for a mistyped word instead of a malformed share.

### Security
- `PassphraseInfo.ToString()` no longer prints the passphrase. It is a `record`, so the
  compiler-generated `ToString` printed every property: a single `$"{info}"` in a log line or an
  exception message wrote the passphrase out in full. The override reports the two lengths and
  nothing else, and the type now documents that it should be treated as secret — `Original`
  holds the passphrase as a string, which cannot be zeroed.
- `Slip39Passphrase.ArePassphrasesEqual` compares with `CryptographicOperations.FixedTimeEquals`
  and zeroes both normalised buffers before returning. `SequenceEqual` returns on the first
  differing byte, which tells anyone who can time the call how much of a guess was right, and
  the buffers were left on the heap — unlike every other passphrase path in the library.
- The secret recovery path now zeroes its intermediate key material, matching the treatment
  the generation path already received. `PolynomialInterpolation.RecoverSecret` clears the
  recovered digest, the HMAC key `R` and the expected digest, and clears the recovered
  secret itself on the failure paths where it never reaches the caller.
  `Slip39ShareCombination.CombineShares` clears the reconstructed group shares and the
  encrypted master secret. Both methods now document that the caller owns — and should
  zero — the array they return.
- `RecoverSecret` compares the share digest with `CryptographicOperations.FixedTimeEquals`
  instead of a byte loop that returned on the first mismatch.
- `RecoverSecret` returns a copy rather than the caller's array in the threshold-1 case.
  Recovering from a single share is a no-op that previously handed back the input, which
  the new ownership contract makes unsafe: for a 1-of-1 group, `CombineShares` would have
  zeroed a `ShareValue` still held by the caller.

  Zeroing managed buffers is best-effort: the GC may relocate an array before the `finally`
  runs, leaving unreachable copies behind, and nothing prevents the memory reaching swap or
  a core dump. It shortens the exposure window rather than eliminating it.

## [1.0.0] - 2025-01-XX

### Added
- First stable release
- Full SLIP-0039 implementation
- Production-ready CLI tool
- Comprehensive documentation

---

## Release Notes

### Version 1.0.0 Features

This initial release provides a complete, production-ready implementation of SLIP-0039 Shamir's Secret Sharing for .NET applications.

**Key Highlights:**
- ✅ **Specification Compliant**: Passes all official SLIP-0039 test vectors
- ✅ **Secure Implementation**: Memory-safe cryptographic operations
- ✅ **Cross-Platform**: Runs on Windows, Linux, and macOS
- ✅ **Well-Tested**: Extensive test suite with >95% code coverage
- ✅ **Easy to Use**: Simple API and intuitive CLI interface

**Security Considerations:**
- Implements SLIP-0039 specification exactly as defined
- Uses industry-standard cryptographic libraries
- Secure memory handling for sensitive data
- Comprehensive input validation and error handling

**Breaking Changes:**
- None (initial release)

**Migration Guide:**
- Not applicable (initial release)

**Known Issues:**
- Minor nullability warnings in test code (non-functional)

**Performance:**
- Optimized Galois Field operations
- Efficient polynomial interpolation
- Fast checksum computation
- Minimal memory allocation during operations
