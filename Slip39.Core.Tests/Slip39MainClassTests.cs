using Xunit;

namespace Slip39.Core.Tests;

/// <summary>
/// Tests for the main Slip39 class functionality, focusing on the high-level API.
/// </summary>
public class Slip39MainClassTests
{
    [Fact]
    public void CombineMnemonics_ValidMnemonics_ShouldReturnSuccess()
    {
        // Arrange
        var masterSecret = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        var passphrase = "test passphrase";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };

        // Generate shares and convert to mnemonics (placeholder - actual mnemonic conversion not implemented)
        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs, masterSecret, passphrase, 0);
        
        // Convert shares to actual mnemonic words
        var mnemonics = shares.Select(s => s.ToMnemonic()).ToArray();

        // Act
        var result = Slip39.CombineMnemonics(mnemonics, passphrase);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(masterSecret, result.MasterSecret);
        Assert.Equal(passphrase, result.Passphrase);
        Assert.Null(result.ErrorMessage);
    }

    [Fact]
    public void CombineMnemonics_NoPassphrase_MeansTheEmptyPassphrase()
    {
        // Arrange - shares made with no passphrase, as SLIP-0039 defines it
        var masterSecret = new byte[16];
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };

        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs, masterSecret, null, 0);
        var mnemonics = shares.Select(s => s.ToMnemonic()).ToArray();

        // Act
        var result = Slip39.CombineMnemonics(mnemonics); // No passphrase provided

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(masterSecret, result.MasterSecret);
        Assert.Equal("", result.Passphrase);
    }

    [Fact]
    public void CombineMnemonics_NoPassphrase_DoesNotSubstituteTrezor()
    {
        // The specification's test vectors use "TREZOR", and this library used to treat that
        // as the default for "no passphrase". Shares made that way are unreadable by any other
        // SLIP-0039 implementation — and not with an error, since nothing can verify a
        // passphrase: the other implementation returns a different secret and reports success.
        var masterSecret = new byte[16];
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };
        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs, masterSecret, "TREZOR", 0);
        var mnemonics = shares.Select(s => s.ToMnemonic()).ToArray();

        var result = Slip39.CombineMnemonics(mnemonics); // no passphrase

        Assert.True(result.IsSuccess);                     // it "succeeds" — that is the danger
        Assert.NotEqual(masterSecret, result.MasterSecret); // with the wrong secret
    }

    [Fact]
    public void CombineMnemonics_NullMnemonics_ShouldReturnFailure()
    {
        // Act
        var result = Slip39.CombineMnemonics(null!);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Equal("Mnemonics array cannot be null", result.ErrorMessage);
        Assert.Empty(result.MasterSecret);
    }

    [Fact]
    public void CombineMnemonics_EmptyMnemonics_ShouldReturnFailure()
    {
        // Act
        var result = Slip39.CombineMnemonics(new string[0]);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Equal("At least one mnemonic is required", result.ErrorMessage);
        Assert.Empty(result.MasterSecret);
    }

    [Fact]
    public void CombineMnemonics_InvalidMnemonic_ShouldReturnFailure()
    {
        // Arrange
        var invalidMnemonics = new[] { "invalid mnemonic format" };

        // Act
        var result = Slip39.CombineMnemonics(invalidMnemonics);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("Failed to parse mnemonic", result.ErrorMessage);
        Assert.Empty(result.MasterSecret);
    }

    [Fact]
    public void CombineMnemonics_EmptyMnemonic_ShouldReturnFailure()
    {
        // Arrange
        var mnemonicsWithEmpty = new[] { "valid hex string", "", "another valid hex" };

        // Act
        var result = Slip39.CombineMnemonics(mnemonicsWithEmpty);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("Failed to parse mnemonic", result.ErrorMessage);
        Assert.Empty(result.MasterSecret);
    }

    [Fact]
    public void CombineMnemonics_NullPassphrase_MeansTheEmptyPassphrase()
    {
        // Arrange
        var masterSecret = new byte[16];
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };
        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs, masterSecret, "", 0);
        var mnemonics = shares.Select(s => s.ToMnemonic()).ToArray();

        // Act
        var result = Slip39.CombineMnemonics(mnemonics, null!);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(masterSecret, result.MasterSecret);
        Assert.Equal("", result.Passphrase);
    }

    [Fact]
    public void CombineMnemonics_ComplexScenario_ShouldWork()
    {
        // Arrange
        var masterSecret = new byte[32];
        for (int i = 0; i < masterSecret.Length; i++)
            masterSecret[i] = (byte)(i + 1);

        var passphrase = "complex passphrase with symbols !@#$%";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
        {
            new(2, 3), // Group 0: 2 of 3 shares
            new(3, 4)  // Group 1: 3 of 4 shares
        };

        var allShares = Slip39ShareGeneration.GenerateShares(2, groupConfigs, masterSecret, passphrase, 2);
        
        // Select minimum required shares
        var selectedShares = new List<Slip39Share>();
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 0).Take(2));
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 1).Take(3));

        var mnemonics = selectedShares.Select(s => s.ToMnemonic()).ToArray();

        // Act
        var result = Slip39.CombineMnemonics(mnemonics, passphrase);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(masterSecret, result.MasterSecret);
        Assert.Equal(passphrase, result.Passphrase);
    }

    [Fact]
    public void CombineMnemonics_InsufficientShares_ShouldReturnFailure()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
        {
            new(2, 3), // Group 0: 2 of 3 shares
            new(2, 2)  // Group 1: 2 of 2 shares
        };

        var allShares = Slip39ShareGeneration.GenerateShares(2, groupConfigs, masterSecret, passphrase, 0);
        
        // Only take shares from one group (insufficient)
        var insufficientShares = allShares.Where(s => s.GroupIndex == 0).Take(2);
        var mnemonics = insufficientShares.Select(s => s.ToMnemonic()).ToArray();

        // Act
        var result = Slip39.CombineMnemonics(mnemonics, passphrase);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("must equal group threshold", result.ErrorMessage);
        Assert.Empty(result.MasterSecret);
    }

    [Fact]
    public void CombineMnemonics_MixedSharesFromDifferentSets_ShouldReturnFailure()
    {
        // Arrange
        var masterSecret1 = new byte[16];
        var masterSecret2 = new byte[16] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        var passphrase = "test";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(2, 2) };

        var shares1 = Slip39ShareGeneration.GenerateShares(1, groupConfigs, masterSecret1, passphrase, 0);
        var shares2 = Slip39ShareGeneration.GenerateShares(1, groupConfigs, masterSecret2, passphrase, 0);

        // Mix shares from different sets
        var mixedMnemonics = new[] { shares1[0].ToMnemonic(), shares2[1].ToMnemonic() };

        // Act
        var result = Slip39.CombineMnemonics(mixedMnemonics, passphrase);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("same identifier", result.ErrorMessage);
        Assert.Empty(result.MasterSecret);
    }

    [Fact]
    public void CombineResult_Success_ShouldCreateValidResult()
    {
        // Arrange
        var masterSecret = new byte[] { 1, 2, 3, 4 };
        var passphrase = "test";

        // Act
        var result = CombineResult.Success(masterSecret, passphrase);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(masterSecret, result.MasterSecret);
        Assert.Equal(passphrase, result.Passphrase);
        Assert.Null(result.ErrorMessage);
    }

    [Fact]
    public void CombineResult_Failure_ShouldCreateValidResult()
    {
        // Arrange
        var errorMessage = "Test error message";

        // Act
        var result = CombineResult.Failure(errorMessage);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Empty(result.MasterSecret);
        Assert.Null(result.Passphrase);
        Assert.Equal(errorMessage, result.ErrorMessage);
    }

    [Fact]
    public void CombineMnemonics_WrongPassphrase_ShouldReturnDifferentSecret()
    {
        // Arrange
        var masterSecret = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        var correctPassphrase = "correct";
        var wrongPassphrase = "wrong";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };

        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs, masterSecret, correctPassphrase, 0);
        var mnemonics = shares.Select(s => s.ToMnemonic()).ToArray();

        // Act
        var result = Slip39.CombineMnemonics(mnemonics, wrongPassphrase);

        // Assert
        Assert.True(result.IsSuccess); // Should succeed but return wrong secret
        Assert.NotEqual(masterSecret, result.MasterSecret);
        Assert.Equal(wrongPassphrase, result.Passphrase);
    }

    [Fact]
    public void CombineMnemonics_LargeNumberOfShares_ShouldWork()
    {
        // Arrange - Test with many groups and shares
        var masterSecret = new byte[32];
        var passphrase = "test";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
        {
            new(3, 5), // Group 0: 3 of 5 shares
            new(4, 7), // Group 1: 4 of 7 shares
            new(2, 3), // Group 2: 2 of 3 shares
            new(3, 4)  // Group 3: 3 of 4 shares
        };

        var allShares = Slip39ShareGeneration.GenerateShares(3, groupConfigs, masterSecret, passphrase, 1);
        
        // Use shares from groups 0, 1, and 2
        var selectedShares = new List<Slip39Share>();
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 0).Take(3));
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 1).Take(4));
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 2).Take(2));

        var mnemonics = selectedShares.Select(s => s.ToMnemonic()).ToArray();

        // Act
        var result = Slip39.CombineMnemonics(mnemonics, passphrase);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(masterSecret, result.MasterSecret);
        Assert.Equal(9, mnemonics.Length); // 3 + 4 + 2 = 9 total shares used
    }

    
    [Fact]
    public void CombineMnemonics_UnicodePassphraseNormalization_ShouldWork()
    {
        // Arrange - Test Unicode passphrase normalization
        var masterSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var originalPassphrase = "e\u0301"; // 'e' with combining acute accent
        var normalizedPassphrase = "é";    // single character é (normalized form)
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };
        
        // Generate shares with original passphrase
        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs, 
            masterSecret, originalPassphrase, 0);
        var mnemonics = shares.Select(s => s.ToMnemonic()).ToArray();
        
        // Act - Combine with normalized passphrase
        var result = Slip39.CombineMnemonics(mnemonics, normalizedPassphrase);
        
        // Assert - Should work because passphrases are equivalent after normalization
        Assert.True(result.IsSuccess);
        Assert.Equal(masterSecret, result.MasterSecret);
    }
    
    [Fact]
    public void CombineMnemonics_EmptyAndNullPassphrase_ShouldBeEquivalent()
    {
        // Arrange
        var masterSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };
        
        // Generate shares with an explicitly empty passphrase
        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs,
            masterSecret, "", 0);
        var mnemonics = shares.Select(s => s.ToMnemonic()).ToArray();

        // Act - Combine with a null passphrase
        var result = Slip39.CombineMnemonics(mnemonics, null!);

        // Assert - null and "" are the same passphrase: none
        Assert.True(result.IsSuccess);
        Assert.Equal(masterSecret, result.MasterSecret);
    }
}
