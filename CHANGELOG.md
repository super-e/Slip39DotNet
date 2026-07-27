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
- New `Slip39.Console.Tests` project covering the command line interface, which previously had
  no tests at all. The tests drive the CLI in process and assert on the exit code and on which
  stream each message goes to, not only on its wording — every CLI defect fixed in this
  release printed a plausible message and still exited 0.

### Documentation
- Complete API documentation
- Usage examples and tutorials
- Security best practices
- Installation and setup guides

### Fixed
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
- `Slip39Share.ToHex()` and `Slip39ShareParser.ParseFromHex()` no longer disagree on the
  bit layout. `ToHex()` appended the share value padding while the parser expected it
  before the value, so a share exported as hex could not be read back — `ParseFromHex()`
  rejected it with "Invalid mnemonic checksum". `ToHex()` now derives its bit stream from
  the same `ShareToIndices` used by `ToMnemonic()`, and `ParseFromHex()` discards the
  trailing byte-alignment slack before parsing.

### Changed
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
