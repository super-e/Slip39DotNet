# SLIP-0039 Console CLI Tool

A comprehensive command-line interface for SLIP-0039 Shamir's Secret Sharing operations.

## Overview

This CLI tool provides a user-friendly interface to:
- Split secrets into SLIP-0039 shares
- Combine shares to recover original secrets  
- Display detailed information about shares
- Validate share checksums
- Generate random secrets and split them

## Installation & Building

Build the project:
```bash
dotnet build
```

Run directly with dotnet:
```bash
dotnet run --project Slip39.Console.csproj -- [command] [options]
```

## Usage

### Basic Commands

| Command | Description |
|---------|-------------|
| `split` | Split a secret into SLIP-0039 shares |
| `split-xpriv` | Split a BIP32 extended private key into SLIP-0039 shares |
| `combine` | Combine SLIP-0039 shares to recover secret |
| `info` | Display detailed information about a share |
| `validate` | Validate SLIP-0039 share checksums, and cross-check shares |
| `generate` | Generate a random secret and split it |
| `help` | Show help message |

Every command returns exit code 0 on success and 1 on failure, and writes its error messages to
stderr. Unrecognised options are an error rather than being ignored — `--treshold 5` used to
produce a 2-of-7 split with nothing to indicate the flag had been dropped.

### Split Command

Split a hexadecimal secret into SLIP-0039 shares.

**Usage:**
```bash
dotnet run -- split --secret <hex> [options]
```

**Options:**
- `--secret <hex>` - Hexadecimal secret to split (required)

**Single Group Mode (Simple):**
- `--threshold <n>` - Number of shares needed to recover (default: 2)
- `--shares <n>` - Total number of shares to generate (default: 3)

**Multi-Group Mode (Advanced):**
- `--group-threshold <n>` - Number of groups needed to recover (default: 1)
- `--groups <config>` - Group configurations in format 'threshold-of-total'
  - Examples: "2-of-3" or "2-of-3,3-of-5,1-of-1"

**Common Options:**
- `--passphrase <p>` - Passphrase (default: none, as SLIP-0039 requires)
- `--iterations <n>` - Iteration exponent 0-15 (default: 0)
- `--extendable` - Generate extendable shares
- `--format <fmt>` - Output format: text, json, hex (default: text)

**Examples:**
```bash
# Split a 256-bit secret into 3 shares, requiring 2 to recover
dotnet run -- split --secret 458d0765afec7bb0fb45a50a84d5bf74d75a2b1e69fd79015ce2bb23a9ce9ef3 --threshold 2 --shares 3

# Split with custom passphrase and higher security
dotnet run -- split --secret 1234abcd --threshold 3 --shares 5 --passphrase mypass --iterations 4

# Output in JSON format
dotnet run -- split --secret 1234abcd --format json

# Multi-group: Company backup (executives OR directors can recover)
dotnet run -- split --secret 1234abcd --group-threshold 1 --groups "2-of-3,3-of-5"

# Multi-group: Bank-style security (need IT AND Legal AND Management)
dotnet run -- split --secret 1234abcd --group-threshold 3 --groups "2-of-3,1-of-1,2-of-4"

# Multi-group: Flexible security (need any 2 out of 3 groups)
dotnet run -- split --secret 1234abcd --group-threshold 2 --groups "2-of-3,1-of-1,3-of-5"
```

### Split-Xpriv Command

Split a BIP32 extended private key into SLIP-0039 shares.

**Usage:**
```bash
dotnet run -- split-xpriv --xpriv <xprv...> [options]
```

Takes the same grouping, passphrase, iteration and format options as `split`, plus:
- `--xpriv <xprv...>` - BIP32 extended private key (required)
- `--show-secret` - Print the private key, chain code and combined secret

These shares are **not a portable BIP-32 backup.** SLIP-0039 requires one to contain the BIP-32
master *seed*, and an xprv does not contain it, so what is split here is the private key and chain
code. The shares are valid SLIP-0039 and any implementation recovers the same 64 bytes — but
another wallet reads them as a seed and derives a different wallet, without reporting an error.
The seed cannot be recovered from an xprv, so this command cannot be made conformant. If you still
have the master seed, back that up with `slip39 split` instead. Recover these shares with
`slip39 combine --bip32 --reconstruct-xpriv`.

`--show-secret` is **off by default**. Those three values are the wallet itself; printing them on
every invocation put them in terminal scrollback, shell history and any logs capturing stdout.

Only a mainnet extended *private* key is accepted. An `xpub` decodes to the same 78 bytes and used
to pass with only a warning — the command then labelled part of the public key "Private Key" and
split it into shares, producing a confident-looking backup that cannot restore a wallet.

**Examples:**
```bash
# Simple backup of a hardware wallet master key
dotnet run -- split-xpriv --xpriv xprv9s21ZrQH... --threshold 2 --shares 3

# Multi-group backup with a custom passphrase
dotnet run -- split-xpriv --xpriv xprv9s21ZrQH... --group-threshold 2 --groups "2-of-3,3-of-5" --passphrase corp2024
```

The resulting shares are recombined with `slip39 combine --bip32 --reconstruct-xpriv`, which
reconstructs the original xprv. Without `--reconstruct-xpriv` the 64 bytes are read as a BIP-32
seed and you get a different key — the same thing another wallet would do.

### Combine Command

Combine SLIP-0039 shares to recover the original secret.

**Usage:**
```bash
dotnet run -- combine [options] "share1" "share2" ["share3" ...]
```

**Options:**
- `--passphrase <p>` - Passphrase (default: none, as SLIP-0039 requires)
- `--format <fmt>` - Output format: hex, base64, binary (default: hex)
- `--bip32` - Also show BIP32 master key
- `--ignore-invalid-shares` - Recover from the sound shares even if some disagree
- `--reconstruct-xpriv` - Read the secret as a private key and chain code from `split-xpriv`,
  instead of as a BIP-32 master seed

With `--bip32` the recovered secret is treated as a BIP-32 master seed, which is what SLIP-0039
requires a backup to contain. Shares made by `split-xpriv` hold a private key and chain code
instead, and need `--reconstruct-xpriv`: nothing in the recovered bytes distinguishes the two, so
the choice has to be yours.

**No passphrase means the empty string**, as the specification requires. Shares created by a
version of this tool from before that was corrected used `"TREZOR"` — recover those with
`--passphrase TREZOR`. Nothing can detect which you have: SLIP-0039 provides no way to verify a
passphrase, so the wrong one returns a different secret and reports success.

Passing more shares than the threshold is allowed: the extra ones are checked against the rest.
By default recovery stops if any of them disagrees, so a backup that has degraded does not pass
unnoticed. `--ignore-invalid-shares` recovers anyway from the shares that do agree, as long as a
quorum remains in every group — someone recovering under pressure should not be blocked by one
share mis-transcribed years ago when the rest are sufficient. The shares that were excluded are
reported, and the recovered secret is verified against its SLIP-0039 digest either way.

**Examples:**
```bash
# Combine two shares
dotnet run -- combine "mild isolate academic acid..." "mild isolate academic agency..."

# Combine with custom passphrase and show BIP32 key
dotnet run -- combine --passphrase mypass --bip32 "share1" "share2"

# Output in base64 format
dotnet run -- combine --format base64 "share1" "share2"

# Recover from three shares when one of them is wrong
dotnet run -- combine --ignore-invalid-shares "share1" "share2" "share3"
```

### Info Command

Display detailed information about a SLIP-0039 share.

**Usage:**
```bash
dotnet run -- info [options] "share mnemonic"
```

**Options:**
- `--format <fmt>` - Output format: text, json, hex (default: text)
- `--no-validate` - Skip checksum validation

**Examples:**
```bash
# Show detailed share information
dotnet run -- info "mild isolate academic acid apart..."

# Output in JSON format
dotnet run -- info --format json "share mnemonic"

# Skip checksum validation
dotnet run -- info --no-validate "potentially invalid share"
```

### Validate Command

Validate SLIP-0039 share checksums, and cross-check the shares against each other.

**Usage:**
```bash
dotnet run -- validate [options] "share1" "share2" ["share3" ...]
```

**Options:**
- `--verbose` - Show detailed validation information

Given two or more shares, they are also cross-checked. A valid checksum only proves one mnemonic
was copied without a typo; the cross-check proves the shares still belong together, which is what
someone testing an old backup wants to know.

**Examples:**
```bash
# Validate multiple shares
dotnet run -- validate "share1" "share2" "share3"

# Verbose validation output
dotnet run -- validate --verbose "share1" "share2"
```

### Generate Command

Generate a random secret and split it into SLIP-0039 shares.

**Usage:**
```bash
dotnet run -- generate [options]
```

**Options:**
- `--bits <n>` - Secret size in bits: 128 or 256 (default: 256)
- `--threshold <n>` - Number of shares needed to recover (default: 2)
- `--shares <n>` - Total number of shares to generate (default: 3)
- `--passphrase <p>` - Passphrase (default: none, as SLIP-0039 requires)
- `--iterations <n>` - Iteration exponent 0-15 (default: 0)
- `--extendable` - Generate extendable shares
- `--format <fmt>` - Output format: text, json, hex (default: text)
- `--show-secret` - Display the generated secret (for verification)
- `--bip32` - Also show BIP32 master key

**Examples:**
```bash
# Generate 256-bit secret with default settings
dotnet run -- generate

# Generate 128-bit secret with custom threshold
dotnet run -- generate --bits 128 --threshold 3 --shares 5

# Show the generated secret and BIP32 key
dotnet run -- generate --show-secret --bip32

# Generate with custom passphrase and JSON output
dotnet run -- generate --passphrase mypass --format json
```

## Output Formats

### Text Format (Default)
Human-readable output with clear formatting and descriptions.

### JSON Format
Structured JSON output suitable for programmatic processing:
```json
{
  "identifier": 23762,
  "extendable": false,
  "iterationExponent": 0,
  "groupIndex": 0,
  "groupThreshold": 0,
  "groupCount": 0,
  "memberIndex": 0,
  "memberThreshold": 1,
  "shareValue": "sUCXy46b1p6hXn9O5ORJag==",
  "checksum": 958672780
}
```

`Slip39ShareParser.ParseFromJson` reads this format back, and now checks it: the fields must be
within their SLIP-0039 bit widths, and `checksum` must be the RS1024 checksum those fields imply.
A share edited by hand — including one given a placeholder checksum, as the example above used to
carry — is rejected rather than silently accepted and re-encoded into a wrong mnemonic.

### Hex Format
Raw hexadecimal representation of the share data.

## Security Notes

1. **Passphrases**: If no passphrase is specified, the empty string is used, as SLIP-0039
   requires. ("TREZOR" is the passphrase the specification's *test vectors* use; this tool used to
   treat it as the default, which made its shares unreadable by other implementations.) Use only
   printable ASCII: the specification requires it for interoperability, and the CLI warns
   otherwise.

2. **Iteration Count**: The iteration count is calculated as 10,000 × 2^e where e is the iteration exponent (0-15).

3. **Share Storage**: Store shares securely and separately. Never store multiple shares in the same location.

4. **Validation**: Always validate shares before relying on them for secret recovery.

## Example Workflow

1. **Generate shares from a secret:**
```bash
dotnet run -- split --secret 458d0765afec7bb0fb45a50a84d5bf74d75a2b1e69fd79015ce2bb23a9ce9ef3 --threshold 2 --shares 3
```

2. **Examine a share:**
```bash
dotnet run -- info "mild isolate academic acid apart..."
```

3. **Validate shares:**
```bash
dotnet run -- validate "share1" "share2" "share3"
```

4. **Recover the original secret:**
```bash
dotnet run -- combine "share1" "share2"
```

## Error Handling

The CLI provides clear error messages for common issues:
- Invalid hexadecimal secrets
- Insufficient shares for recovery
- Checksum validation failures
- Invalid mnemonic words
- Parameter validation errors

Exit codes:
- 0: Success
- 1: Error occurred

## Dependencies

This CLI tool depends on the Slip39.Core library which implements:
- SLIP-0039 specification compliance
- Reed-Solomon RS1024 checksums
- Shamir's Secret Sharing algorithms
- PBKDF2 encryption/decryption
- BIP32 master key generation

## SLIP-0039 Specification Compliance

This implementation follows the official SLIP-0039 specification:
- Correct bit encoding and endianness
- Proper checksum validation
- Standard wordlist usage
- Compliant encryption parameters
- Full support for both extendable and non-extendable shares
