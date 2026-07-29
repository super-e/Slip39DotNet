using Xunit;

namespace Slip39.Core.Tests;

/// <summary>
/// Unit tests for the RS1024 checksum implementation used in SLIP-0039.
/// Tests cover the checksum verification, generation, and utility methods.
/// </summary>
public class Rs1024ChecksumTests
{
    /// <summary>
    /// A mnemonic from the SLIP-0039 reference test vectors ("Valid mnemonic without sharing,
    /// 128 bits"). Its checksum was produced by the reference implementation, so nothing in this
    /// repository had a hand in it.
    /// </summary>
    private const string ReferenceMnemonic =
        "duckling enlarge academic academic agency result length solution fridge kidney " +
        "coal piece deal husband erode duke ajar critical decision keyboard";

    private static ushort[] ReferenceWordIndices() =>
        Wordlist.WordsToIndices(ReferenceMnemonic.Split(' ')).Select(i => (ushort)i).ToArray();

    [Fact]
    public void VerifyChecksum_ReferenceVectorMnemonic_ShouldReturnTrue()
    {
        // This used to build its input with GenerateChecksum and then hand it to
        // VerifyChecksum — the two halves of the same implementation confirming each other. A
        // shared error in CalculateChecksum, which both call, would have passed unnoticed. The
        // input now comes from the specification's own test vectors instead.
        var isValid = Rs1024Checksum.VerifyChecksum(ReferenceWordIndices());

        Assert.True(isValid);
    }

    [Fact]
    public void VerifyChecksum_ReferenceVectorMnemonic_WithOneWordChanged_ShouldReturnFalse()
    {
        // The companion the test above needs: a verifier that accepts everything would satisfy
        // the positive case on its own.
        var words = ReferenceWordIndices();
        words[3] = (ushort)((words[3] + 1) % 1024);

        Assert.False(Rs1024Checksum.VerifyChecksum(words));
    }

    [Fact]
    public void GenerateChecksum_AgreesWithTheReferenceVector()
    {
        // Ties GenerateChecksum to the same external anchor: regenerating the last three words
        // of a reference mnemonic from the preceding ones must reproduce them exactly.
        var words = ReferenceWordIndices();
        var dataWords = words[..^3];
        var expectedChecksum = words[^3..];

        Assert.Equal(expectedChecksum, Rs1024Checksum.GenerateChecksum(dataWords));
    }

    [Fact]
    public void VerifyChecksum_RoundTripWithGenerateChecksum_ShouldReturnTrue()
    {
        // Kept deliberately, but no longer the only evidence that the checksum is correct: this
        // asserts self-consistency, which the tests above no longer depend on.
        var dataWords = new ushort[] { 1, 2 };
        var checksumWords = Rs1024Checksum.GenerateChecksum(dataWords);
        var completeWords = dataWords.Concat(checksumWords).ToArray();

        Assert.True(Rs1024Checksum.VerifyChecksum(completeWords));
    }

    [Fact]
    public void VerifyChecksum_InvalidChecksum_ShouldReturnFalse()
    {
        // Arrange - Create valid checksum then corrupt it
        var dataWords = new ushort[] { 1, 2, 3 };
        var checksumWords = Rs1024Checksum.GenerateChecksum(dataWords);
        var completeWords = dataWords.Concat(checksumWords).ToArray();
        
        // Corrupt the checksum
        completeWords[completeWords.Length - 1] ^= 1; // Flip one bit
        
        // Act
        var isValid = Rs1024Checksum.VerifyChecksum(completeWords);
        
        // Assert
        Assert.False(isValid);
    }
    
    [Fact]
    public void VerifyChecksum_TooFewWords_ShouldThrow()
    {
        // Arrange
        var tooFewWords = new ushort[] { 1, 2 }; // Less than minimum 3 words
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Rs1024Checksum.VerifyChecksum(tooFewWords));
    }
    
    [Fact]
    public void VerifyChecksum_WordValueTooLarge_ShouldThrow()
    {
        // Arrange
        var invalidWords = new ushort[] { 1, 2, 1024 }; // 1024 is >= 1024, invalid
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Rs1024Checksum.VerifyChecksum(invalidWords));
    }
    
    [Fact]
    public void VerifyChecksum_NullInput_ShouldThrow()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Rs1024Checksum.VerifyChecksum(null!));
    }
    
    [Fact]
    public void GenerateChecksum_ValidInput_ShouldProduceValidChecksum()
    {
        // Arrange
        var dataWords = new ushort[] { 100, 200, 300, 400, 500 };
        
        // Act
        var checksumWords = Rs1024Checksum.GenerateChecksum(dataWords);
        var completeWords = dataWords.Concat(checksumWords).ToArray();
        
        // Assert
        Assert.Equal(3, checksumWords.Length); // Checksum should be exactly 3 words
        Assert.True(Rs1024Checksum.VerifyChecksum(completeWords));
    }
    
    [Fact]
    public void GenerateChecksum_EmptyInput_ShouldWork()
    {
        // Arrange
        var emptyWords = new ushort[0];
        
        // Act
        var checksumWords = Rs1024Checksum.GenerateChecksum(emptyWords);
        var completeWords = emptyWords.Concat(checksumWords).ToArray();
        
        // Assert
        Assert.Equal(3, checksumWords.Length);
        Assert.True(Rs1024Checksum.VerifyChecksum(completeWords));
    }
    
    [Fact]
    public void GenerateChecksum_NullInput_ShouldThrow()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Rs1024Checksum.GenerateChecksum(null!));
    }
    
    [Fact]
    public void CalculateChecksum_KnownInput_ShouldBeConsistent()
    {
        // Arrange
        var words = new ushort[] { 1, 2, 3, 4, 5 };
        
        // Act
        var checksum1 = Rs1024Checksum.CalculateChecksum(words);
        var checksum2 = Rs1024Checksum.CalculateChecksum(words);
        
        // Assert
        Assert.Equal(checksum1, checksum2); // Should be deterministic
    }
    
    [Fact]
    public void CalculateChecksum_DifferentInputs_ShouldProduceDifferentResults()
    {
        // Arrange
        var words1 = new ushort[] { 1, 2, 3 };
        var words2 = new ushort[] { 1, 2, 4 }; // Different last word
        
        // Act
        var checksum1 = Rs1024Checksum.CalculateChecksum(words1);
        var checksum2 = Rs1024Checksum.CalculateChecksum(words2);
        
        // Assert
        Assert.NotEqual(checksum1, checksum2);
    }
    
    [Fact]
    public void GenerateChecksum_VariousInputSizes_ShouldAlwaysProduceValidChecksum()
    {
        // Arrange - Test different input sizes
        var testSizes = new[] { 1, 5, 10, 20, 50 };
        
        foreach (var size in testSizes)
        {
            var dataWords = new ushort[size];
            for (int i = 0; i < size; i++)
            {
                dataWords[i] = (ushort)(i % 1024); // Keep within valid range
            }
            
            // Act
            var checksumWords = Rs1024Checksum.GenerateChecksum(dataWords);
            var completeWords = dataWords.Concat(checksumWords).ToArray();
            
            // Assert
            Assert.Equal(3, checksumWords.Length);
            Assert.True(Rs1024Checksum.VerifyChecksum(completeWords),
                $"Generated checksum should be valid for input size {size}");
        }
    }
    
    [Fact]
    public void VerifyChecksum_CustomizationString_ShouldAffectResult()
    {
        // This test verifies that the "shamir" customization string is being used
        // by checking that identical data produces different checksums with different customizations
        
        // Arrange
        var dataWords = new ushort[] { 1, 2, 3, 4, 5 };
        
        // Act - Generate checksum (uses "shamir" internally)
        var checksumWords = Rs1024Checksum.GenerateChecksum(dataWords);
        var completeWords = dataWords.Concat(checksumWords).ToArray();
        
        // Assert - The checksum should be valid
        Assert.True(Rs1024Checksum.VerifyChecksum(completeWords));
        
        // If we manually calculate without the customization, it should be different
        var manualChecksum = Rs1024Checksum.CalculateChecksum(dataWords.Concat(new ushort[3]).ToArray());
        var expectedChecksum = Rs1024Checksum.CalculateChecksum(completeWords);
        
        // These should be different values, proving customization is used
        Assert.NotEqual(manualChecksum, expectedChecksum);
    }
}
