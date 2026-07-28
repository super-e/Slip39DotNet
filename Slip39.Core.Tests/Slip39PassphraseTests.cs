using System.Text;
using Xunit;

namespace Slip39.Core.Tests;

/// <summary>
/// Unit tests for SLIP-0039 passphrase normalization and handling.
/// Verifies compliance with SLIP-0039 specification.
/// </summary>
public class Slip39PassphraseTests
{
    /// <summary>
    /// SLIP-0039: "If no passphrase is provided, an empty string SHALL be used as the
    /// passphrase." These used to assert the opposite — that no passphrase meant "TREZOR",
    /// the passphrase the specification's own test vectors use — which is what made every
    /// share produced without an explicit passphrase unreadable by any other implementation.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void NormalizePassphrase_NoPassphrase_IsTheEmptyString(string? passphrase)
    {
        var result = Slip39Passphrase.NormalizePassphrase(passphrase);

        Assert.Empty(result);
    }

    [Fact]
    public void NormalizePassphrase_NoPassphrase_IsNotTrezor()
    {
        // Named separately because it is the specific regression, and because a reader who
        // knows the test vectors will wonder.
        Assert.NotEqual(Encoding.UTF8.GetBytes("TREZOR"), Slip39Passphrase.NormalizePassphrase(null));
    }

    [Theory]
    [InlineData("correct horse battery staple", true)]
    [InlineData(" !~", true)]                 // the ends of the printable ASCII range
    [InlineData("", true)]                    // no passphrase is portable
    [InlineData("café", false)]               // non-ASCII
    [InlineData("two\nlines", false)]         // control character
    public void IsPortablePassphrase_FollowsTheSpecificationsAsciiRule(string passphrase, bool expected)
    {
        // SLIP-0039 requires printable ASCII (32-126) "in order to achieve the best
        // interoperability among various operating systems and wallet implementations".
        Assert.Equal(expected, Slip39Passphrase.IsPortablePassphrase(passphrase));
    }

    [Fact]
    public void NormalizePassphrase_UnicodeCharacters_ShouldBeNormalized()
    {
        // Arrange
        var input = "Å̈"; // Angstrom with combining diaeresis
        
        // Act
        var normalized = Slip39Passphrase.NormalizePassphrase(input);

        // Assert
        // NFKD normalization decomposes characters fully
        var expectedNormalized = input.Normalize(NormalizationForm.FormKD);
        Assert.Equal(Encoding.UTF8.GetBytes(expectedNormalized), normalized);
    }

    [Fact]
    public void ValidatePassphrase_ValidUnicode_ShouldReturnTrue()
    {
        // Arrange
        var input = "Å̈BCDℱ"; 

        // Act
        var isValid = Slip39Passphrase.ValidatePassphrase(input);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void ValidatePassphrase_InvalidControlCharacters_ShouldReturnFalse()
    {
        // Arrange
        var input = "Valid text \u007F"; // DEL control character

        // Act
        var isValid = Slip39Passphrase.ValidatePassphrase(input);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void PreparePassphrase_InvalidPassphrase_ShouldThrow()
    {
        // Arrange
        var input = "Valid text \u007F"; // DEL control character

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39Passphrase.PreparePassphrase(input));
    }

    [Fact]
    public void ArePassphrasesEqual_DifferentNormalizationForms_ShouldReturnTrue()
    {
        // Arrange
        var passphrase1 = "e\u0301"; // 'e' with combining acute accent
        var passphrase2 = "é";       // single character é

        // Act
        var areEqual = Slip39Passphrase.ArePassphrasesEqual(passphrase1, passphrase2);

        // Assert
        Assert.True(areEqual);
    }

    [Fact]
    public void MaximumPassphraseEntropyBits_VariousCharacters_ShouldProvideReasonableEstimate()
    {
        // Arrange
        var passphrase = "abcDEF123!@#\u2764"; // Includes Unicode heart

        // Act
        var entropy = Slip39Passphrase.MaximumPassphraseEntropyBits(passphrase);

        // Assert
        Assert.True(entropy > 0);
    }

    [Fact]
    public void EstimatePassphraseEntropy_ForwardsToItsReplacement()
    {
        // The old name is kept as an obsolete alias, so callers keep compiling.
#pragma warning disable CS0618 // Type or member is obsolete
        var viaOldName = Slip39Passphrase.EstimatePassphraseEntropy("abcDEF123!@#");
#pragma warning restore CS0618
        Assert.Equal(Slip39Passphrase.MaximumPassphraseEntropyBits("abcDEF123!@#"), viaOldName);
    }

    [Fact]
    public void MaximumPassphraseEntropyBits_IsAnUpperBound_NotAStrengthRating()
    {
        // "Password1!" is a dictionary word with the two most predictable decorations there
        // are, and it still scores like ten uniformly random characters from the same alphabet.
        // This is the documented behaviour of the method, not a defect in it \u2014 the test is here
        // so that anyone tempted to treat the number as a strength score sees the counterexample.
        var weak = Slip39Passphrase.MaximumPassphraseEntropyBits("Password1!");
        var random = Slip39Passphrase.MaximumPassphraseEntropyBits("T7q!vZ2m#K");

        Assert.Equal(random, weak, precision: 10);
        Assert.True(weak > 60);
    }
    
    [Fact]
    public void PreparePassphrase_ValidPassphrase_ShouldReturnCompleteInfo()
    {
        // Arrange
        var passphrase = "Hello World";
        
        // Act
        var info = Slip39Passphrase.PreparePassphrase(passphrase);
        
        // Assert
        Assert.Equal(passphrase, info.Original);
        Assert.Equal(passphrase.Length, info.OriginalLength);
        Assert.Equal(Encoding.UTF8.GetBytes(passphrase), info.NormalizedBytes);
        Assert.Equal(Encoding.UTF8.GetBytes(passphrase).Length, info.NormalizedByteLength);
    }
    
    [Fact]
    public void PassphraseInfo_ToString_DoesNotContainThePassphrase()
    {
        // The compiler-generated ToString of a record prints every property, so one interpolated
        // "{info}" in a log line or an exception message wrote the passphrase out in full.
        var passphrase = "correct horse battery staple";

        var text = Slip39Passphrase.PreparePassphrase(passphrase).ToString();

        Assert.DoesNotContain(passphrase, text, StringComparison.Ordinal);
        Assert.DoesNotContain("correct", text, StringComparison.Ordinal);
        Assert.Contains("PassphraseInfo", text, StringComparison.Ordinal);
        Assert.Contains("28", text, StringComparison.Ordinal); // the length is not secret
    }

    [Fact]
    public void ArePassphrasesEqual_DifferentPassphrases_ShouldReturnFalse()
    {
        Assert.False(Slip39Passphrase.ArePassphrasesEqual("alpha", "beta"));
        Assert.False(Slip39Passphrase.ArePassphrasesEqual("alpha", "alphaa"));
        Assert.False(Slip39Passphrase.ArePassphrasesEqual("alpha", null)); // null means no passphrase
    }

    [Fact]
    public void ValidatePassphrase_CommonWhitespace_ShouldBeValid()
    {
        // Arrange
        var passphrase = "Hello\tWorld\nTest\r";
        
        // Act
        var isValid = Slip39Passphrase.ValidatePassphrase(passphrase);
        
        // Assert
        Assert.True(isValid);
    }
    
    [Fact]
    public void ValidatePassphrase_ExtremelyLongPassphrase_ShouldBeFalse()
    {
        // Arrange
        var longPassphrase = new string('a', 1001); // Exceeds 1000 character limit
        
        // Act
        var isValid = Slip39Passphrase.ValidatePassphrase(longPassphrase);
        
        // Assert
        Assert.False(isValid);
    }
    
    [Fact]
    public void ArePassphrasesEqual_NullAndEmpty_ShouldReturnTrue()
    {
        // Act - Both null and empty should resolve to "TREZOR" default
        var areEqual = Slip39Passphrase.ArePassphrasesEqual(null, "");
        
        // Assert
        Assert.True(areEqual);
    }
    
    [Fact]
    public void MaximumPassphraseEntropyBits_EmptyPassphrase_ShouldReturnZero()
    {
        // Act - Empty passphrase should be treated as null for entropy estimation
        var entropy = Slip39Passphrase.MaximumPassphraseEntropyBits("");
        
        // Assert - Empty input to entropy estimation returns 0
        Assert.Equal(0.0, entropy);
    }
    
    [Fact]
    public void MaximumPassphraseEntropyBits_LowercaseOnly_ShouldReturnReasonableEntropy()
    {
        // Arrange
        var passphrase = "lowercase";

        // Act
        var entropy = Slip39Passphrase.MaximumPassphraseEntropyBits(passphrase);
        
        // Assert
        // Should be approximately passphrase.Length * log2(26)
        var expectedEntropy = passphrase.Length * Math.Log2(26);
        Assert.True(Math.Abs(entropy - expectedEntropy) < 0.1);
    }
    
    [Fact]
    public void PassphraseWithEncryption_DifferentNormalizedForms_ShouldProduceSameResult()
    {
        // Arrange
        var passphrase1 = "e\u0301"; // 'e' with combining acute accent
        var passphrase2 = "é";       // single character é
        var masterSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        ushort identifier = 123;
        byte iterationExponent = 0;
        bool isExtendable = false;
        
        // Act
        var encrypted1 = Slip39Encryption.Encrypt(masterSecret, passphrase1, iterationExponent, identifier, isExtendable);
        var encrypted2 = Slip39Encryption.Encrypt(masterSecret, passphrase2, iterationExponent, identifier, isExtendable);
        
        // Assert
        Assert.Equal(encrypted1, encrypted2);
    }
    
    [Fact]
    public void PassphraseWithEncryption_DecryptionWithNormalizedForm_ShouldWork()
    {
        // Arrange
        var originalPassphrase = "e\u0301"; // 'e' with combining acute accent
        var decryptPassphrase = "é";       // single character é (normalized form)
        var masterSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        ushort identifier = 123;
        byte iterationExponent = 0;
        bool isExtendable = false;
        
        // Act
        var encrypted = Slip39Encryption.Encrypt(masterSecret, originalPassphrase, iterationExponent, identifier, isExtendable);
        var decrypted = Slip39Encryption.Decrypt(encrypted, decryptPassphrase, iterationExponent, identifier, isExtendable);
        
        // Assert
        Assert.Equal(masterSecret, decrypted);
    }
    
    [Theory]
    [InlineData("")]
    [InlineData("simple")]
    [InlineData("Test123!@#")]
    [InlineData("Ελληνικά")]  // Greek
    [InlineData("日本語")]      // Japanese
    [InlineData("🔐🚀")]       // Emojis
    public void PassphraseNormalization_VariousInputs_ShouldBeConsistent(string passphrase)
    {
        // Act
        var normalized1 = Slip39Passphrase.NormalizePassphrase(passphrase);
        var normalized2 = Slip39Passphrase.NormalizePassphrase(passphrase);
        
        // Assert
        Assert.Equal(normalized1, normalized2);
    }
}

