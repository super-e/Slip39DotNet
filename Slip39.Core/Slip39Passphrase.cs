using System.Globalization;
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
    public static bool ArePassphrasesEqual(string? passphrase1, string? passphrase2)
    {
        var normalized1 = NormalizePassphrase(passphrase1);
        var normalized2 = NormalizePassphrase(passphrase2);
        
        return normalized1.SequenceEqual(normalized2);
    }
    
    /// <summary>
    /// Estimates the entropy of a passphrase based on its character composition.
    /// This is useful for providing feedback to users about passphrase strength.
    /// </summary>
    /// <param name="passphrase">The passphrase to analyze</param>
    /// <returns>Estimated entropy in bits</returns>
    public static double EstimatePassphraseEntropy(string? passphrase)
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
public record PassphraseInfo(
    string Original,
    byte[] NormalizedBytes,
    int OriginalLength,
    int NormalizedByteLength
);
