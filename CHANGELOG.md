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

### Documentation
- Complete API documentation
- Usage examples and tutorials
- Security best practices
- Installation and setup guides

### Fixed
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
