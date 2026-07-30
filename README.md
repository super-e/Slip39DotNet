# SLIP-0039 .NET Implementation

[![.NET](https://img.shields.io/badge/.NET-9.0-blue.svg)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

A complete .NET implementation of [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) Shamir's Secret Sharing for mnemonic codes, providing both a core library and a command-line interface.

## Features

- ✅ **Complete SLIP-0039 Implementation** - Full compliance with the specification
- ✅ **Shamir's Secret Sharing** - Split secrets into multiple shares with configurable thresholds
- ✅ **Multi-Group Support** - Advanced group-based sharing with flexible recovery strategies
- ✅ **BIP32 Extended Key Support** - Split and recover BIP32 extended private keys (xprv)
- ✅ **BIP32 Master Key Generation** - Generate HD wallet master keys from recovered secrets
- ✅ **Passphrase Support** - Optional passphrase protection for enhanced security
- ✅ **Command Line Interface** - Comprehensive CLI for all operations
- ✅ **Cross-Platform** - Runs on Windows, Linux, and macOS
- ✅ **Comprehensive Testing** - Extensive test suite with official test vectors
- ✅ **Memory Safety** - Secure handling of sensitive cryptographic material

## Breaking Changes (unreleased)

The unreleased version changes behaviour in ways that will break existing callers. Each entry
says what to do about it; the [CHANGELOG](CHANGELOG.md) explains why.

> **Read this one first.** No passphrase now means the **empty string**, as SLIP-0039 requires.
> This library used to substitute `"TREZOR"`, the passphrase the specification's *test vectors*
> use. Shares created by an earlier version of this tool **without an explicit passphrase** need
> `--passphrase TREZOR` (or `CombineShares(shares, "TREZOR")`) to recover. Nothing will tell you:
> SLIP-0039 has no way to verify a passphrase, so the wrong one returns a different secret and
> reports success.

### Library

| Change | What breaks | What to do |
|---|---|---|
| No passphrase means the empty string, not `"TREZOR"` | Shares made by an earlier version of *this* library with no passphrase | Recover them with the passphrase `"TREZOR"`, once; re-split with no passphrase to get a portable backup |
| `Bip32MasterKey.GenerateMasterKey` / `Slip39.GenerateMasterKey` are `[Obsolete]` in their two-argument form | Compiler warning | Drop the passphrase argument — it was never used. BIP-32 derivation takes no passphrase; the passphrase belongs to `CombineShares` |
| `Slip39ShareCombination.CombineShares` requires **exactly** the member threshold from each group | Passing extra shares now throws | Pass exactly *T* shares per group, or call `VerifyShares` first to check the rest |
| `Slip39ShareGeneration.CombineShares` is `[Obsolete]` | Compiler warning | Call `Slip39ShareCombination.CombineShares`, which it now forwards to |
| `Slip39Share.ToHex()` / `ParseFromHex()` use the canonical SLIP-0039 bit layout | Hex written by earlier versions no longer parses | Re-export affected shares from their mnemonic form. Mnemonic and JSON are unaffected |
| `Slip39Share` has no parameterless constructor and its fields are `init`-only | Object initialisers and property assignment no longer compile | Use the ten-argument constructor, which validates the field ranges |
| `Slip39ShareParser.ParseFromJson` validates field ranges and the RS1024 checksum | JSON shares with a wrong or placeholder checksum are rejected | Give hand-built shares a real checksum, or build them through the constructor and `ToJson` |
| `Wordlist.Words` returns `IReadOnlyList<string>` | Assigning it to a `string[]`, or writing through it, no longer compiles | Read it as `IReadOnlyList<string>`; indexing and enumeration are unchanged |
| The wordlist is loaded only from the embedded resource, and verified on load | A `wordlist.txt` placed next to the DLL is ignored | Nothing, unless you were substituting the wordlist — which is what this prevents |
| `Rs1024Checksum.BytesToWords`, `WordsToBytes` and `BytesToWordsExact` are removed | Compile error | Use `Slip39ShareParser.ShareToIndices`. The removed helpers did not produce the SLIP-0039 share layout |
| `Slip39Passphrase.EstimatePassphraseEntropy` is `[Obsolete]` | Compiler warning | Call `MaximumPassphraseEntropyBits`, and read its documentation before trusting the number |

Not breaking, but worth knowing when you upgrade: the recovery path
(`PolynomialInterpolation.RecoverSecret` and `Slip39ShareCombination.CombineShares`) now zeroes
its intermediate key material, and both document that the caller owns — and should zero — the
array they return. `RecoverSecret` also returns a copy rather than the caller's own array in the
threshold-1 case, so recovering from a 1-of-1 group no longer zeroes a `ShareValue` you still
hold.

### CLI

| Change | What breaks |
|---|---|
| Failures return exit code 1 and write to **stderr** | Scripts that treated exit 0 as success were previously told nothing had failed. This is a fix, but it changes what your scripts see |
| An unrecognised option is an error | `split --treshold 5 --shares 7` used to silently produce a 2-of-7 split. It now fails |
| `split-xpriv` prints the private key and chain code only with `--show-secret` | Anything parsing that output must pass the flag |
| `split-xpriv` rejects anything that is not a mainnet extended **private** key | An `xpub` used to pass with a warning and be split into an unusable backup |
| `combine` refuses to recover from a set of shares that contradicts itself | Add `--ignore-invalid-shares` to recover from the shares that do agree, provided a quorum remains |
| `combine` with no `--passphrase` uses the empty passphrase | Shares split by an earlier version of this tool with no passphrase now recover to a **different secret, silently**. Pass `--passphrase TREZOR` |
| `combine --bip32` reads a 64-byte secret as a BIP-32 seed | Backups made with `split-xpriv` need `--reconstruct-xpriv`. Nothing in the recovered bytes distinguishes the two readings, so the choice has to be explicit |

## Interoperability

The shares this library produces are recovered by other SLIP-0039 implementations, and vice
versa. This is checked against [Trezor's `shamir-mnemonic`](https://pypi.org/project/shamir-mnemonic/),
the reference Python implementation, in both directions across 128/256/512-bit secrets,
extendable and non-extendable shares, iteration exponents 0 and 2, 1-of-1, 2-of-3, and multiple
groups — with and without a passphrase. Six vectors generated by that implementation ship in the
test suite (`Slip39.Core.Tests/interop-vectors.json`), four of them with **no** passphrase: the
specification's own vectors all use `"TREZOR"`, so nothing otherwise exercises the default.

Two things to know before trusting a backup to another wallet:

- **Use a printable-ASCII passphrase.** The specification requires it "in order to achieve the
  best interoperability among various operating systems and wallet implementations". Outside that
  range the bytes depend on the Unicode normalisation each implementation applies; this library
  warns when generating shares with such a passphrase.
- **`split-xpriv` is not a portable BIP-32 backup.** SLIP-0039 requires a BIP-32 backup to
  contain the master *seed*, and an xprv does not contain it — `split-xpriv` splits the private
  key and chain code instead. The shares are valid SLIP-0039 and any implementation will recover
  the same 64 bytes, but another wallet reads them as a seed and derives a **different wallet**,
  without reporting an error. If you still have the master seed, back that up with
  `slip39 split`. To recover a `split-xpriv` backup with this tool, use
  `slip39 combine --bip32 --reconstruct-xpriv`.

## Quick Start

### Installation

#### Using .NET CLI
```bash
git clone https://github.com/yourusername/Slip39DotNet.git
cd Slip39DotNet
dotnet build
```

#### Using the CLI Tool
```bash
# Split a 256-bit secret into shares
dotnet run --project Slip39.Console split --secret "a1b2c3d4e5f67890abcdef1234567890fedcba0987654321a1b2c3d4e5f67890" --threshold 2 --shares 3

# Combine shares to recover the secret
dotnet run --project Slip39.Console combine "mnemonic1" "mnemonic2"

# Split a BIP32 extended private key into shares
dotnet run --project Slip39.Console split-xpriv --xpriv "xprv9s21ZrQH143K..." --threshold 2 --shares 3

# Generate random secret and split into shares
dotnet run --project Slip39.Console generate --bits 256 --threshold 2 --shares 3
```

### Library Usage

```csharp
using Slip39.Core;

// Split a 128-bit secret into shares
var secret = Convert.FromHexString("a1b2c3d4e5f67890abcdef1234567890");
var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(2, 3) };
var shares = Slip39ShareGeneration.GenerateShares(
    groupThreshold: 1,
    groupConfigs: groupConfigs,
    masterSecret: secret,
    passphrase: "optional_passphrase"
);

// Convert shares to mnemonics
var mnemonics = shares.Select(share => share.ToMnemonic()).ToArray();

// Later, combine shares to recover the secret.
// Pass exactly the member threshold from each group — no more: SLIP-0039 requires it, and
// surplus shares would otherwise be discarded without ever being checked.
var recoveredSecret = Slip39ShareCombination.CombineShares(shares.Take(2).ToList(), "optional_passphrase");
Console.WriteLine($"Recovered: {Convert.ToHexString(recoveredSecret)}");

// To check every share you hold rather than the threshold-many recovery consumes —
// "is my backup still intact?" — use VerifyShares. It needs no passphrase and returns no secret.
var report = Slip39ShareCombination.VerifyShares(shares);
foreach (var bad in report.Inconsistent)
    Console.WriteLine($"Share {bad.Share.MemberIndex} of group {bad.Share.GroupIndex}: {bad.Detail}");

// Generate BIP32 master key from recovered secret
var masterKey = Bip32MasterKey.GenerateMasterKey(recoveredSecret, "optional_passphrase");
Console.WriteLine($"Master Key: {masterKey}");
```

### Multi-Group Shares

SLIP-0039 supports multi-group shares, allowing you to create different groups with separate recovery thresholds. This provides more flexible recovery strategies.

```csharp
using Slip39.Core;

// Define a 256-bit secret
var secret = Convert.FromHexString("a1b2c3d4e5f67890abcdef1234567890fedcba0987654321a1b2c3d4e5f67890");

// Define groups with their thresholds and share counts
var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
{
    new(2, 3), // Group 1: 2-of-3 shares needed
    new(1, 2)  // Group 2: 1-of-2 shares needed  
};

// Generate multi-group shares (need 1 group to recover)
var shares = Slip39ShareGeneration.GenerateShares(
    groupThreshold: 1,
    groupConfigs: groupConfigs,
    masterSecret: secret,
    passphrase: "optional_passphrase"
);

// Convert shares to mnemonics
var mnemonics = shares.Select(share => share.ToMnemonic()).ToArray();

// To recover the secret, you need to meet the threshold for at least one group
// For example, provide 2 shares from Group 1 OR 1 share from Group 2
var group1Shares = shares.Where(s => s.GroupIndex == 0).Take(2).ToList();
var recoveredSecret = Slip39ShareCombination.CombineShares(group1Shares, "optional_passphrase");
Console.WriteLine($"Recovered: {Convert.ToHexString(recoveredSecret)}");
```

### BIP32 Extended Private Key Support

SLIP39DotNet provides native support for backing up BIP32 extended private keys (xprv) using SLIP-0039 shares. This allows you to securely backup and recover HD wallet master keys.

```csharp
using Slip39.Core;

// Your BIP32 extended private key (from hardware wallet, etc.)
var originalXpriv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

// Decode and extract the private key and chain code (64 bytes total)
var extendedKeyData = Base58Check.Decode(originalXpriv);
var privateKey = new byte[32];
var chainCode = new byte[32];
Array.Copy(extendedKeyData, 46, privateKey, 0, 32); // Private key at offset 46
Array.Copy(extendedKeyData, 13, chainCode, 0, 32);  // Chain code at offset 13

// Combine into 64-byte master secret
var masterSecret = new byte[64];
Array.Copy(privateKey, 0, masterSecret, 0, 32);
Array.Copy(chainCode, 0, masterSecret, 32, 32);

// Generate SLIP-0039 shares from the BIP32 key
var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(2, 3) };
var shares = Slip39ShareGeneration.GenerateShares(
    groupThreshold: 1,
    groupConfigs: groupConfigs,
    masterSecret: masterSecret,
    passphrase: "TREZOR", // Standard passphrase
    iterationExponent: 0,
    isExtendable: false);

// Later, recover the original xprv from shares
var recoveredSecret = Slip39ShareCombination.CombineShares(shares.Take(2).ToList(), "TREZOR");

// Reconstruct the BIP32 extended private key
// ... (BIP32 reconstruction logic)
var reconstructedXpriv = ReconstructBip32ExtendedKey(recoveredSecret);
Console.WriteLine($"Recovered xprv: {reconstructedXpriv}");
```

**Key Features:**
- **Full xprv Recovery**: Exactly reconstructs the original BIP32 extended private key
- **64-byte Secrets**: Handles the full private key (32 bytes) + chain code (32 bytes)
- **Long Mnemonics**: Generates 59-word mnemonics for 64-byte secrets
- **CLI Integration**: Use `split-xpriv` and `combine --bip32` commands

## Projects

### Slip39.Core
The core library implementing SLIP-0039 specification:
- **Slip39ShareGeneration** - Create mnemonic shares from secrets
- **Slip39ShareCombination** - Recover secrets from shares  
- **Slip39ShareParser** - Parse and validate mnemonic strings
- **Slip39Encryption** - SLIP-0039 encryption/decryption with PBKDF2 and Feistel network
- **Bip32MasterKey** - Generate BIP32 extended private keys
- **Base58Check** - Base58Check encoding/decoding for BIP32 keys
- **Cryptographic primitives** - GF(256) operations, polynomial interpolation, RS1024 checksums
- **Multi-group support** - Advanced group-based sharing configurations

### Slip39.Console  
Command-line interface providing:
- **split** - Split secrets into mnemonic shares
- **split-xpriv** - Split BIP32 extended private keys into shares
- **combine** - Combine shares to recover secrets
- **combine --bip32** - Recover and reconstruct BIP32 extended private keys
- **combine --ignore-invalid-shares** - Recover from the shares that agree when some do not
- **info** - Display detailed share information
- **validate** - Validate share checksums, and cross-check shares against each other
- **generate** - Generate random secrets and split into shares
- **Multi-format output** - Text, JSON, and hex output formats

## CLI Commands

### Basic Secret Sharing

```bash
# Split a 128-bit secret into shares (single group)
dotnet run --project Slip39.Console split --secret "a1b2c3d4e5f67890abcdef1234567890" --threshold 2 --shares 3

# Split a 256-bit secret into multi-group shares
# Create 2 groups: Group 1 (3-of-5) and Group 2 (2-of-3) - need 1 group to recover
dotnet run --project Slip39.Console split --secret "a1b2c3d4e5f67890abcdef1234567890fedcba0987654321a1b2c3d4e5f67890" --group-threshold 1 --groups "3-of-5,2-of-3"

# Multi-group requiring 2 out of 3 groups to recover
dotnet run --project Slip39.Console split --secret "a1b2c3d4e5f67890abcdef1234567890fedcba0987654321a1b2c3d4e5f67890" --group-threshold 2 --groups "2-of-3,3-of-5,1-of-1" --passphrase "mypassword"

# Combine shares to recover secret
dotnet run --project Slip39.Console combine "share1" "share2"

# Combine shares and show BIP32 master key
dotnet run --project Slip39.Console combine --bip32 "share1" "share2"
```

### BIP32 Extended Private Key Support

```bash
# Split a BIP32 extended private key (xprv) into SLIP-0039 shares
dotnet run --project Slip39.Console split-xpriv --xpriv "xprv9s21ZrQH143K..." --threshold 2 --shares 3

# Same, also printing the private key and chain code. Off by default: they are the wallet
# itself, and would otherwise land in terminal scrollback and logs on every invocation.
dotnet run --project Slip39.Console split-xpriv --xpriv "xprv9s21ZrQH143K..." --threshold 2 --shares 3 --show-secret

# Split with custom passphrase and multi-group configuration
dotnet run --project Slip39.Console split-xpriv --xpriv "xprv9s21ZrQH143K..." --group-threshold 2 --groups "2-of-3,3-of-5" --passphrase "mypassword"

# Combine shares to recover the original BIP32 extended private key
dotnet run --project Slip39.Console combine --bip32 "share1" "share2"
```

### Share Management

```bash
# Get detailed information about a share
dotnet run --project Slip39.Console info "share_mnemonic"

# Validate share checksums, and cross-check the shares against each other
dotnet run --project Slip39.Console validate "share1" "share2" "share3"

# Recover even though one share is wrong, as long as a quorum of sound ones remains
dotnet run --project Slip39.Console combine --ignore-invalid-shares "share1" "share2" "share3"

# Generate random secret and split into shares
dotnet run --project Slip39.Console generate --bits 256 --threshold 2 --shares 3

# Generate with BIP32 master key output
dotnet run --project Slip39.Console generate --bits 256 --threshold 2 --shares 3 --bip32 --show-secret
```

For detailed CLI usage, see [Slip39.Console/README.md](Slip39.Console/README.md).

## Security Considerations

- **Cryptographic Compliance**: Implements SLIP-0039 specification exactly as defined
- **Secure Memory**: Sensitive data is handled securely and cleared when possible
- **Passphrase Protection**: Optional passphrase adds an additional layer of security
- **Threshold Security**: Requires minimum number of shares to recover secrets
- **Checksum Validation**: RS1024 checksums detect a mnemonic that was mis-transcribed
- **Cross-checking**: a valid checksum only proves one mnemonic was copied correctly. `VerifyShares`
  and `slip39 validate` check that the shares still agree with each other, which is the question
  someone testing an old backup is actually asking

⚠️ **Important**: Keep your mnemonic shares secure and backed up. Loss of shares below the threshold means permanent loss of your secret.

## Testing

The project includes comprehensive tests covering:
- SLIP-0039 reference test vectors
- BIP32 master key derivation
- Cryptographic primitives (GF256, polynomial interpolation)
- Error handling and edge cases
- CLI functionality

```bash
# Run all tests
dotnet test

# Run with coverage
dotnet test --collect:"XPlat Code Coverage"
```

## Requirements

- .NET 9.0 or later
- Supported platforms: Windows, Linux, macOS

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Specification

This implementation follows the [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) specification published by SatoshiLabs.

## Acknowledgments

- SatoshiLabs for the SLIP-0039 specification
- The Bitcoin community for BIP32 specification
- Adi Shamir for Shamir's Secret Sharing algorithm

## AI Development Disclaimer

🤖 **This entire repository was completely vibe-coded with AI coding agents.** Not a single line of code, comment, documentation, or ancillary file was edited manually. The SLIP-0039 .NET implementation, CLI application, tests, documentation, and project infrastructure were all generated through AI-assisted development in the terminal.

Two agents were used:

- **Warp AI Terminal Agent Mode** — the initial implementation and the bulk of the project.
- **Claude Code** (models Sonnet 5 and Opus 5) — subsequent work, including specification-compliance fixes, test hardening, security review, and the CI pipeline.

## Disclaimer

This software is provided as-is. While it implements the SLIP-0039 specification and passes all test vectors, users should thoroughly test and audit the code for their specific use cases. The authors are not responsible for any loss of funds or data.
