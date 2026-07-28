using Xunit;

namespace Slip39.Core.Tests;

/// <summary>
/// Tests for SLIP-0039 share generation, encryption, and combination functionality.
/// </summary>
public class Slip39ShareGenerationTests
{
    [Fact]
    public void GenerateShares_BasicScenario_ShouldSucceed()
    {
        // Arrange
        var masterSecret = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        var passphrase = "test passphrase";
        byte iterationExponent = 0;
        int groupThreshold = 2;
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
        {
            new(2, 3), // Group 0: 2 of 3 shares
            new(3, 5), // Group 1: 3 of 5 shares
            new(1, 1)  // Group 2: 1 of 1 share
        };

        // Act
        var shares = Slip39ShareGeneration.GenerateShares(groupThreshold, groupConfigs, 
            masterSecret, passphrase, iterationExponent);

        // Assert
        Assert.Equal(9, shares.Count); // 3 + 5 + 1 = 9 total shares
        
        // Verify all shares have the same identifier, ext, e, GT, G
        var firstShare = shares[0];
        foreach (var share in shares)
        {
            Assert.Equal(firstShare.Identifier, share.Identifier);
            Assert.Equal(firstShare.IsExtendable, share.IsExtendable);
            Assert.Equal(firstShare.IterationExponent, share.IterationExponent);
            Assert.Equal(firstShare.GroupThreshold, share.GroupThreshold);
            Assert.Equal(firstShare.GroupCount, share.GroupCount);
        }
        
        // Verify group structure
        Assert.True(firstShare.IsExtendable); // Always true in our implementation
        Assert.Equal(iterationExponent, firstShare.IterationExponent);
        Assert.Equal(groupThreshold - 1, firstShare.GroupThreshold); // Encoded as GT - 1
        Assert.Equal(groupConfigs.Count - 1, firstShare.GroupCount); // Encoded as G - 1
        
        // Verify shares are grouped correctly
        var sharesByGroup = shares.GroupBy(s => s.GroupIndex).ToList();
        Assert.Equal(3, sharesByGroup.Count);
        
        Assert.Equal(3, sharesByGroup.Single(g => g.Key == 0).Count()); // Group 0: 3 shares
        Assert.Equal(5, sharesByGroup.Single(g => g.Key == 1).Count()); // Group 1: 5 shares
        Assert.Equal(1, sharesByGroup.Single(g => g.Key == 2).Count()); // Group 2: 1 share
    }

    [Fact]
    public void GenerateAndCombineShares_RoundTrip_ShouldRecoverOriginalSecret()
    {
        // Arrange
        var masterSecret = new byte[32]; // 256-bit secret
        for (int i = 0; i < masterSecret.Length; i++)
            masterSecret[i] = (byte)(i + 1);
        
        var passphrase = "test passphrase 123";
        byte iterationExponent = 1;
        int groupThreshold = 2;
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
        {
            new(2, 3), // Group 0: 2 of 3 shares
            new(2, 2), // Group 1: 2 of 2 shares
            new(1, 1)  // Group 2: 1 of 1 share
        };

        // Act - Generate shares
        var allShares = Slip39ShareGeneration.GenerateShares(groupThreshold, groupConfigs, 
            masterSecret, passphrase, iterationExponent);

        // Select minimum required shares to test recovery
        var selectedShares = new List<Slip39Share>();
        
        // Take 2 shares from group 0 (need 2 of 3)
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 0).Take(2));
        
        // Take 2 shares from group 1 (need 2 of 2)  
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 1).Take(2));
        
        // Don't take any from group 2 since we only need 2 groups total

        // Act - Combine shares
        var recoveredSecret = Slip39ShareCombination.CombineShares(selectedShares, passphrase);

        // Assert
        Assert.Equal(masterSecret, recoveredSecret);
    }

    [Fact]
    public void GenerateShares_InvalidMasterSecretLength_ShouldThrow()
    {
        // Arrange
        var shortSecret = new byte[15]; // Less than 16 bytes
        var oddLengthSecret = new byte[17]; // Odd length
        var passphrase = "test";
        byte iterationExponent = 0;
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareGeneration.GenerateShares(1, groupConfigs, 
            shortSecret, passphrase, iterationExponent));
        
        Assert.Throws<ArgumentException>(() => Slip39ShareGeneration.GenerateShares(1, groupConfigs, 
            oddLengthSecret, passphrase, iterationExponent));
    }

    [Fact]
    public void GenerateShares_InvalidGroupConfiguration_ShouldThrow()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test";
        byte iterationExponent = 0;

        // Act & Assert
        
        // Group threshold too large
        Assert.Throws<ArgumentException>(() => Slip39ShareGeneration.GenerateShares(17, 
            new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) }, masterSecret, passphrase, iterationExponent));
        
        // Group threshold exceeds group count
        Assert.Throws<ArgumentException>(() => Slip39ShareGeneration.GenerateShares(2, 
            new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) }, masterSecret, passphrase, iterationExponent));
        
        // Member threshold = 1 but count > 1
        Assert.Throws<ArgumentException>(() => Slip39ShareGeneration.GenerateShares(1, 
            new List<Slip39ShareGeneration.GroupConfig> { new(1, 2) }, masterSecret, passphrase, iterationExponent));
    }

    [Fact]
    public void CombineShares_InsufficientShares_ShouldThrow()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test";
        byte iterationExponent = 0;
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
        {
            new(2, 3), // Group 0: 2 of 3 shares
            new(2, 2)  // Group 1: 2 of 2 shares
        };

        var allShares = Slip39ShareGeneration.GenerateShares(2, groupConfigs, 
            masterSecret, passphrase, iterationExponent);

        // Act & Assert
        
        // Only take 1 share from group 0 (need 2)
        var insufficientShares = allShares.Where(s => s.GroupIndex == 0).Take(1).ToList();
        Assert.Throws<ArgumentException>(() => Slip39ShareCombination.CombineShares(insufficientShares, passphrase));
        
        // Only provide 1 group (need 2)
        var oneGroupShares = allShares.Where(s => s.GroupIndex == 0).Take(2).ToList();
        Assert.Throws<ArgumentException>(() => Slip39ShareCombination.CombineShares(oneGroupShares, passphrase));
    }

    [Fact]
    public void CombineShares_WrongPassphrase_ShouldNotRecoverCorrectSecret()
    {
        // Arrange
        var masterSecret = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        var correctPassphrase = "correct passphrase";
        var wrongPassphrase = "wrong passphrase";
        byte iterationExponent = 0;
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };

        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs, 
            masterSecret, correctPassphrase, iterationExponent);

        // Act
        var recoveredWithWrongPassphrase = Slip39ShareCombination.CombineShares(shares, wrongPassphrase);

        // Assert
        Assert.NotEqual(masterSecret, recoveredWithWrongPassphrase);
    }

    [Fact]
    public void GenerateShares_DifferentIterationExponents_ShouldWork()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };

        // Act & Assert - Test various iteration exponents
        for (byte e = 0; e <= 15; e++)
        {
            var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs, 
                masterSecret, passphrase, e);
            
            Assert.Single(shares);
            Assert.Equal(e, shares[0].IterationExponent);
            
            // Verify round-trip works
            var recovered = Slip39ShareCombination.CombineShares(shares, passphrase);
            Assert.Equal(masterSecret, recovered);
        }
    }

    [Theory]
    [InlineData(16)]  // 128-bit
    [InlineData(32)]  // 256-bit
    [InlineData(64)]  // 512-bit
    public void GenerateShares_VariousSecretLengths_ShouldWork(int secretLength)
    {
        // Arrange
        var masterSecret = new byte[secretLength];
        for (int i = 0; i < secretLength; i++)
            masterSecret[i] = (byte)(i % 256);
        
        var passphrase = "test";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };

        // Act
        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs, 
            masterSecret, passphrase, 0);
        
        var recovered = Slip39ShareCombination.CombineShares(shares, passphrase);

        // Assert
        Assert.Equal(masterSecret, recovered);
        Assert.Equal(secretLength, shares[0].ShareValue.Length);
    }

    [Fact]
    public void GenerateShares_ComplexGroupStructure_ShouldWork()
    {
        // Arrange - Test a complex group structure
        var masterSecret = new byte[32];
        var passphrase = "complex test";
        byte iterationExponent = 2;
        int groupThreshold = 3; // Need 3 groups out of 4
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
        {
            new(2, 5), // Group 0: 2 of 5 shares
            new(3, 7), // Group 1: 3 of 7 shares
            new(1, 1), // Group 2: 1 of 1 share (fixed to comply with SLIP-0039)
            new(4, 6)  // Group 3: 4 of 6 shares
        };

        // Act
        var allShares = Slip39ShareGeneration.GenerateShares(groupThreshold, groupConfigs, 
            masterSecret, passphrase, iterationExponent);

        // Select shares from first 3 groups (skip group 3)
        var selectedShares = new List<Slip39Share>();
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 0).Take(2)); // 2 from group 0
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 1).Take(3)); // 3 from group 1
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 2).Take(1)); // 1 from group 2

        var recovered = Slip39ShareCombination.CombineShares(selectedShares, passphrase);

        // Assert
        Assert.Equal(19, allShares.Count); // 5 + 7 + 1 + 6 = 19 total shares
        Assert.Equal(masterSecret, recovered);
    }

    [Fact]
    public void GenerateShares_EmptyPassphrase_MeansNoPassphrase()
    {
        // Arrange
        var masterSecret = new byte[16];
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };

        // Act
        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs,
            masterSecret, "", 0);

        // Assert - "" and null are the same passphrase, and it is not "TREZOR". This used to
        // assert that shares made with "" were recovered with "TREZOR".
        Assert.Single(shares);
        Assert.Equal(masterSecret, Slip39ShareCombination.CombineShares(shares, null));
        Assert.NotEqual(masterSecret, Slip39ShareCombination.CombineShares(shares, "TREZOR"));
    }
    [Fact]
    public void CombineShares_MixedSharesFromDifferentSets_ShouldThrow()
    {
        // Arrange - Generate two different share sets
        var masterSecret1 = new byte[16];
        var masterSecret2 = new byte[16];
        masterSecret2[0] = 0xFF; // Make them different
        
        var passphrase = "test";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(2, 2) }; // Changed to 2 of 2 to avoid threshold=1 with count>1

        var shares1 = Slip39ShareGeneration.GenerateShares(1, groupConfigs, 
            masterSecret1, passphrase, 0);
        
        var shares2 = Slip39ShareGeneration.GenerateShares(1, groupConfigs, 
            masterSecret2, passphrase, 0);

        // Act & Assert - Mix shares from different sets
        var mixedShares = new List<Slip39Share> { shares1[0], shares2[1] };
        Assert.Throws<ArgumentException>(() => Slip39ShareCombination.CombineShares(mixedShares, passphrase));
    }
}
