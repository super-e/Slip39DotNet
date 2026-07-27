using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Slip39.Core;

/// <summary>
/// Implements SLIP-0039 passphrase normalization and handling according to the specification.
/// This includes Unicode normalization and proper encoding for use in the encryption process.
/// </summary>
public static class Slip39Passphrase
{
    /// <summary>
    /// Normalizes a passphrase according to SLIP-0039 specification.
    /// Applies NFKD Unicode normalization as required by the specification.
    /// </summary>
    /// <param name="passphrase">The raw passphrase string</param>
    /// <returns>The passphrase as UTF-8 bytes</returns>
    /// <exception cref="ArgumentNullException">Thrown when passphrase is null</exception>
    /// <remarks>
    /// Callers own the returned array and may zero it: this method must keep returning a
    /// freshly allocated buffer on every call. Caching or interning the result would let
    /// <c>Slip39Encryption.Feistel</c>, which zeroes these bytes once the round key has been
    /// derived, silently corrupt every subsequent call.
    /// </remarks>
    public static byte[] NormalizePassphrase(string? passphrase)
    {
        // Handle null or empty passphrase as "TREZOR" default according to SLIP-0039
        if (string.IsNullOrEmpty(passphrase))
            passphrase = "TREZOR";
        
        // Apply NFKD Unicode normalization as required by SLIP-0039 specification
        var normalizedPassphrase = passphrase.Normalize(NormalizationForm.FormKD);
        
        // Encode as UTF-8 bytes
        return Encoding.UTF8.GetBytes(normalizedPassphrase);
    }
    
    /// <summary>
    /// Validates that a passphrase meets SLIP-0039 requirements.
    /// According to the specification, passphrases should be valid Unicode strings
    /// and may have length restrictions for practical use.
    /// </summary>
    /// <param name="passphrase">The passphrase to validate</param>
    /// <returns>True if the passphrase is valid, false otherwise</returns>
    public static bool ValidatePassphrase(string? passphrase)
    {
        // Null or empty passphrases default to "TREZOR" and are valid
        if (string.IsNullOrEmpty(passphrase))
            return true;
        
        try
        {
            // Try to normalize the passphrase to check for invalid Unicode
            var normalized = passphrase.Normalize(NormalizationForm.FormKD);
            
            // Check for reasonable length limits
            // This is not strictly required by SLIP-0039 but is practical for implementation
            if (passphrase.Length > 1000) // Arbitrary but reasonable limit
                return false;
            
            // Check that the normalized form doesn't contain control characters
            // that might cause issues (except for common whitespace)
            foreach (char c in normalized)
            {
                var category = CharUnicodeInfo.GetUnicodeCategory(c);
                
                // Allow most characters but exclude problematic control characters
                if (category == UnicodeCategory.Control && 
                    c != '\t' && c != '\n' && c != '\r' && c != ' ')
                {
                    return false;
                }
            }
            
            return true;
        }
        catch (ArgumentException)
        {
            // Invalid Unicode string
            return false;
        }
    }
    
    /// <summary>
    /// Creates a passphrase for use in the encryption/decryption process.
    /// This method handles the complete passphrase preparation including normalization.
    /// </summary>
    /// <param name="passphrase">The raw passphrase</param>
    /// <returns>A PassphraseInfo object containing the processed passphrase data</returns>
    /// <exception cref="ArgumentException">Thrown when the passphrase is invalid</exception>
    public static PassphraseInfo PreparePassphrase(string? passphrase)
    {
        if (!ValidatePassphrase(passphrase))
            throw new ArgumentException("Invalid passphrase format");
        
        var normalizedBytes = NormalizePassphrase(passphrase);
        var originalLength = passphrase?.Length ?? 0;
        var normalizedLength = normalizedBytes.Length;
        
        return new PassphraseInfo(
            Original: passphrase ?? "",
            NormalizedBytes: normalizedBytes,
            OriginalLength: originalLength,
            NormalizedByteLength: normalizedLength
        );
    }
    
    /// <summary>
    /// Compares two passphrases for equality using normalized forms.
    /// This ensures that passphrases that are visually identical but use different
    /// Unicode encodings are treated as equal.
    /// </summary>
    /// <param name="passphrase1">The first passphrase</param>
    /// <param name="passphrase2">The second passphrase</param>
    /// <returns>True if the passphrases are equivalent after normalization</returns>
    /// <remarks>
    /// The comparison is constant time with respect to the passphrase contents, and both
    /// normalised buffers are zeroed before returning — the same treatment
    /// <c>Slip39Encryption.Feistel</c> gives them. <c>SequenceEqual</c> returns on the first
    /// differing byte, which tells an attacker who can time this call how much of a guess was
    /// right.
    /// </remarks>
    public static bool ArePassphrasesEqual(string? passphrase1, string? passphrase2)
    {
        var normalized1 = NormalizePassphrase(passphrase1);
        var normalized2 = NormalizePassphrase(passphrase2);

        try
        {
            return CryptographicOperations.FixedTimeEquals(normalized1, normalized2);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(normalized1);
            CryptographicOperations.ZeroMemory(normalized2);
        }
    }
    
    /// <summary>
    /// Estimates the entropy of a passphrase based on its character composition.
    /// </summary>
    /// <param name="passphrase">The passphrase to analyze</param>
    /// <returns>Estimated entropy in bits</returns>
    [Obsolete("Renamed to MaximumPassphraseEntropyBits, which says what the number is: an upper " +
              "bound assuming every character was chosen uniformly at random. It is not an " +
              "estimate of how hard a passphrase is to guess and must not be used to decide " +
              "whether one is strong enough.")]
    public static double EstimatePassphraseEntropy(string? passphrase)
        => MaximumPassphraseEntropyBits(passphrase);

    /// <summary>
    /// Returns the number of bits a passphrase of this length <em>could</em> carry, given the
    /// character classes it draws on: <c>length × log2(alphabet size)</c>.
    /// </summary>
    /// <param name="passphrase">The passphrase to analyze</param>
    /// <returns>An upper bound on the passphrase's entropy, in bits</returns>
    /// <remarks>
    /// This is an upper bound, and for a human-chosen passphrase a wildly loose one: it assumes
    /// every character was drawn uniformly at random, so <c>Password1!</c> scores about 65 bits
    /// — the same as ten random characters from the same alphabet. It measures which character
    /// classes appear, nothing more, and cannot see a dictionary word, a keyboard walk or a
    /// substitution. Use it to say "this passphrase cannot be stronger than N bits"; do not use
    /// it to decide that a passphrase is good enough to protect a wallet.
    /// </remarks>
    public static double MaximumPassphraseEntropyBits(string? passphrase)
    {
        if (string.IsNullOrEmpty(passphrase))
            return 0.0;
        
        var normalized = passphrase.Normalize(NormalizationForm.FormKD);
        
        // Count character types
        bool hasLowercase = false;
        bool hasUppercase = false;
        bool hasDigits = false;
        bool hasSymbols = false;
        bool hasExtended = false;
        
        foreach (char c in normalized)
        {
            if (char.IsLower(c))
                hasLowercase = true;
            else if (char.IsUpper(c))
                hasUppercase = true;
            else if (char.IsDigit(c))
                hasDigits = true;
            else if (char.IsSymbol(c) || char.IsPunctuation(c))
                hasSymbols = true;
            else if (c > 127) // Non-ASCII characters
                hasExtended = true;
        }
        
        // Estimate character space size
        int characterSpace = 0;
        if (hasLowercase) characterSpace += 26;
        if (hasUppercase) characterSpace += 26;
        if (hasDigits) characterSpace += 10;
        if (hasSymbols) characterSpace += 32; // Approximate
        if (hasExtended) characterSpace += 1000; // Very rough estimate for Unicode
        
        if (characterSpace == 0)
            return 0.0;
        
        // Calculate entropy: length * log2(characterSpace)
        return normalized.Length * Math.Log2(characterSpace);
    }
}

/// <summary>
/// Contains information about a processed passphrase.
/// </summary>
/// <param name="Original">The original passphrase string</param>
/// <param name="NormalizedBytes">The normalized passphrase as UTF-8 bytes</param>
/// <param name="OriginalLength">The length of the original passphrase in characters</param>
/// <param name="NormalizedByteLength">The length of the normalized passphrase in bytes</param>
/// <remarks>
/// <c>Original</c> holds the passphrase itself, as a string that cannot be zeroed. Treat the whole
/// object as secret: keep it out of logs, exception messages and crash dumps, and let it go out of
/// scope as soon as <c>NormalizedBytes</c> has been consumed.
/// </remarks>
public record PassphraseInfo(
    string Original,
    byte[] NormalizedBytes,
    int OriginalLength,
    int NormalizedByteLength
)
{
    /// <summary>
    /// Returns a description of the passphrase that does not contain the passphrase.
    /// </summary>
    /// <remarks>
    /// The compiler-generated <c>ToString</c> of a record prints every property, so a single
    /// <c>$"{info}"</c> in a log line or an exception message wrote the passphrase out in full.
    /// </remarks>
    public override string ToString() =>
        $"PassphraseInfo {{ OriginalLength = {OriginalLength}, " +
        $"NormalizedByteLength = {NormalizedByteLength} }}";
}
