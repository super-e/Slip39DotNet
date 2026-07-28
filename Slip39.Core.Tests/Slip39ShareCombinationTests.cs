using Xunit;

namespace Slip39.Core.Tests;

/// <summary>
/// Tests for SLIP-0039 share combination functionality according to the specification.
/// </summary>
public class Slip39ShareCombinationTests
{
    /// <summary>
    /// CombineShares zeroes the group shares it reconstructs, but those belong to it, not to
    /// the caller. A 1-of-1 group is where the two could be confused: recovering a group share
    /// from a single member share is a no-op that could hand back the caller's own ShareValue,
    /// and zeroing that would destroy the share the caller still holds. Recombining the same
    /// list twice is the cheapest way to catch it — the second attempt would see wiped shares.
    /// </summary>
    [Fact]
    public void CombineShares_SingleMemberGroups_LeavesCallerSharesIntact()
    {
        // Arrange — every group is 1-of-1, so each group share is recovered at threshold 1
        var masterSecret = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                          0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        var passphrase = "test passphrase";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
        {
            new(1, 1), // Group 0: 1 of 1
            new(1, 1)  // Group 1: 1 of 1
        };

        var shares = Slip39ShareGeneration.GenerateShares(2, groupConfigs, masterSecret, passphrase, 0);
        var shareValuesBefore = shares.Select(s => (byte[])s.ShareValue.Clone()).ToList();

        // Act
        var first = Slip39ShareCombination.CombineShares(shares, passphrase);

        // Assert — the input shares survive untouched, so a second pass still works
        Assert.Equal(masterSecret, first);
        Assert.Equal(shareValuesBefore, shares.Select(s => s.ShareValue).ToList());

        var second = Slip39ShareCombination.CombineShares(shares, passphrase);
        Assert.Equal(masterSecret, second);
    }

    [Fact]
    public void CombineShares_BasicScenario_ShouldRecoverMasterSecret()
    {
        // Arrange
        var masterSecret = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        var passphrase = "test passphrase";
        byte iterationExponent = 0;
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
        {
            new(2, 3), // Group 0: 2 of 3 shares
            new(2, 2)  // Group 1: 2 of 2 shares
        };

        // Generate shares
        var allShares = Slip39ShareGeneration.GenerateShares(2, groupConfigs, 
            masterSecret, passphrase, iterationExponent);

        // Select minimum required shares
        var selectedShares = new List<Slip39Share>();
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 0).Take(2));
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 1).Take(2));

        // Act
        var recovered = Slip39ShareCombination.CombineShares(selectedShares, passphrase);

        // Assert
        Assert.Equal(masterSecret, recovered);
    }

    [Fact]
    public void CombineShares_ComplexGroupStructure_ShouldWork()
    {
        // Arrange
        var masterSecret = new byte[32];
        for (int i = 0; i < masterSecret.Length; i++)
            masterSecret[i] = (byte)(i + 1);

        var passphrase = "complex test";
        byte iterationExponent = 1;
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
        {
            new(3, 5), // Group 0: 3 of 5 shares
            new(2, 4), // Group 1: 2 of 4 shares
            new(1, 1), // Group 2: 1 of 1 share
            new(4, 6)  // Group 3: 4 of 6 shares
        };

        // Generate shares (need 3 groups out of 4)
        var allShares = Slip39ShareGeneration.GenerateShares(3, groupConfigs, 
            masterSecret, passphrase, iterationExponent);

        // Select shares from groups 0, 1, and 2
        var selectedShares = new List<Slip39Share>();
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 0).Take(3));
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 1).Take(2));
        selectedShares.AddRange(allShares.Where(s => s.GroupIndex == 2).Take(1));

        // Act
        var recovered = Slip39ShareCombination.CombineShares(selectedShares, passphrase);

        // Assert
        Assert.Equal(masterSecret, recovered);
    }

    [Fact]
    public void ValidateShares_ValidShares_ShouldNotThrow()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
        {
            new(2, 2), // Group 0: 2 of 2 shares
            new(2, 2)  // Group 1: 2 of 2 shares
        };

        var allShares = Slip39ShareGeneration.GenerateShares(2, groupConfigs, 
            masterSecret, passphrase, 0);

        // Act & Assert
        Slip39ShareCombination.ValidateShares(allShares); // Should not throw
    }

    [Fact]
    public void ValidateShares_DifferentIdentifiers_ShouldThrow()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };

        var shares1 = Slip39ShareGeneration.GenerateShares(1, groupConfigs, 
            masterSecret, passphrase, 0);
        var shares2 = Slip39ShareGeneration.GenerateShares(1, groupConfigs, 
            masterSecret, passphrase, 0);

        // Mix shares from different sets (they'll have different identifiers)
        var mixedShares = new List<Slip39Share> { shares1[0], shares2[0] };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareCombination.ValidateShares(mixedShares));
    }

    [Fact]
    public void ValidateShares_DifferentIterationExponents_ShouldThrow()
    {
        // Arrange - Create shares with different iteration exponents
        var share1 = new Slip39Share(123, true, 0, 0, 0, 0, 0, 0, new byte[16], 0);
        var share2 = new Slip39Share(123, true, 1, 0, 0, 0, 1, 0, new byte[16], 0); // Different iteration exponent

        var shares = new List<Slip39Share> { share1, share2 };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareCombination.ValidateShares(shares));
    }

    [Fact]
    public void ValidateShares_InsufficientGroups_ShouldThrow()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
        {
            new(2, 2), // Group 0: 2 of 2 shares
            new(2, 2)  // Group 1: 2 of 2 shares
        };

        var allShares = Slip39ShareGeneration.GenerateShares(2, groupConfigs, 
            masterSecret, passphrase, 0);

        // Only take shares from one group (need 2 groups)
        var insufficientShares = allShares.Where(s => s.GroupIndex == 0).ToList();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareCombination.ValidateShares(insufficientShares));
    }

    [Fact]
    public void ValidateShares_DuplicateMemberIndices_ShouldThrow()
    {
        // Arrange - Create shares with duplicate member indices in the same group
        var share1 = new Slip39Share(123, true, 0, 0, 1, 1, 0, 1, new byte[16], 0);
        var share2 = new Slip39Share(123, true, 0, 0, 1, 1, 0, 1, new byte[16], 0); // Same member index

        var shares = new List<Slip39Share> { share1, share2 };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareCombination.ValidateShares(shares));
    }

    [Fact]
    public void ValidateShares_MismatchedMemberThresholds_ShouldThrow()
    {
        // Arrange - Create shares in the same group with different member thresholds
        var share1 = new Slip39Share(123, true, 0, 0, 1, 1, 0, 1, new byte[16], 0);
        var share2 = new Slip39Share(123, true, 0, 0, 1, 1, 1, 0, new byte[16], 0); // Different member threshold

        var shares = new List<Slip39Share> { share1, share2 };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareCombination.ValidateShares(shares));
    }

    [Fact]
    public void ValidateShares_IncorrectMemberCount_ShouldThrow()
    {
        // Arrange - Create a scenario where member count doesn't equal member threshold
        var share1 = new Slip39Share(123, true, 0, 0, 1, 1, 0, 2, new byte[16], 0); // Member threshold = 3, but only 1 share

        var shares = new List<Slip39Share> { share1 };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareCombination.ValidateShares(shares));
    }

    [Fact]
    public void ValidateShares_ShortShareValue_ShouldThrow()
    {
        // Arrange - Create share with share value less than 128 bits
        var share = new Slip39Share(123, true, 0, 0, 0, 0, 0, 0, new byte[15], 0); // 120 bits < 128 bits

        var shares = new List<Slip39Share> { share };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareCombination.ValidateShares(shares));
    }

    [Fact]
    public void ValidateShares_EmptySharesList_ShouldThrow()
    {
        // Arrange
        var shares = new List<Slip39Share>();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareCombination.ValidateShares(shares));
    }

    [Fact]
    public void CombineShares_WrongPassphrase_ShouldNotRecoverCorrectSecret()
    {
        // Arrange
        var masterSecret = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        var correctPassphrase = "correct";
        var wrongPassphrase = "wrong";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };

        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs, 
            masterSecret, correctPassphrase, 0);

        // Act
        var recoveredWithWrongPassphrase = Slip39ShareCombination.CombineShares(shares, wrongPassphrase);

        // Assert
        Assert.NotEqual(masterSecret, recoveredWithWrongPassphrase);
    }

    [Fact]
    public void CombineShares_NullPassphrase_MeansNoPassphrase()
    {
        // Arrange
        var masterSecret = new byte[16];
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };

        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs,
            masterSecret, null, 0);

        // Act
        var recovered = Slip39ShareCombination.CombineShares(shares, null!);

        // Assert
        Assert.Equal(masterSecret, recovered);
    }

    [Fact]
    public void CombineShares_DifferentSecretLengths_ShouldWork()
    {
        // Arrange
        var testLengths = new[] { 16, 32, 64 }; // 128, 256, 512 bits

        foreach (var length in testLengths)
        {
            var masterSecret = new byte[length];
            for (int i = 0; i < length; i++)
                masterSecret[i] = (byte)(i % 256);

            var passphrase = "test";
            var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(1, 1) };

            var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs, 
                masterSecret, passphrase, 0);

            // Act
            var recovered = Slip39ShareCombination.CombineShares(shares, passphrase);

            // Assert
            Assert.Equal(masterSecret, recovered);
        }
    }

    [Fact]
    public void CombineShares_MaximumComplexity_ShouldWork()
    {
        // Arrange - Test maximum allowed complexity: 16 groups, need 8
        var masterSecret = new byte[32];
        var passphrase = "max complexity test";
        byte iterationExponent = 3;

        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>();
        for (int i = 0; i < 8; i++) // Create 8 groups
        {
            groupConfigs.Add(new(2, 3)); // Each group: 2 of 3 shares
        }

        var allShares = Slip39ShareGeneration.GenerateShares(8, groupConfigs, 
            masterSecret, passphrase, iterationExponent);

        // Select exactly the threshold number of shares from each group
        var selectedShares = new List<Slip39Share>();
        for (int groupIndex = 0; groupIndex < 8; groupIndex++)
        {
            selectedShares.AddRange(allShares.Where(s => s.GroupIndex == groupIndex).Take(2));
        }

        // Act
        var recovered = Slip39ShareCombination.CombineShares(selectedShares, passphrase);

        // Assert
        Assert.Equal(masterSecret, recovered);
    }

    [Fact]
    public void ValidateShares_GroupCountVsThreshold_Validation()
    {
        // Arrange - Create a share where group count < group threshold (invalid)
        var invalidShare = new Slip39Share(
            identifier: 123,
            isExtendable: true,
            iterationExponent: 0,
            groupIndex: 0,
            groupThreshold: 2, // GT = 3 (encoded as 2)
            groupCount: 1,     // G = 2 (encoded as 1) - this is invalid since G < GT
            memberIndex: 0,
            memberThreshold: 0,
            shareValue: new byte[16],
            checksum: 0
        );

        var shares = new List<Slip39Share> { invalidShare };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareCombination.ValidateShares(shares));
    }

    [Fact]
    public void CombineShares_ExtraShares_AreRejectedRatherThanDiscarded()
    {
        // This test used to assert that surplus shares "still work". They did — by being
        // dropped unread, which is what let a corrupt share past the threshold go unreported.
        // SLIP-0039 requires exactly the threshold per group; VerifyShares is the supported
        // way to check every share you hold.
        var masterSecret = new byte[16];
        var passphrase = "test";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
        {
            new(2, 4), // Group 0: 2 of 4 shares
            new(3, 5)  // Group 1: 3 of 5 shares
        };

        var allShares = Slip39ShareGeneration.GenerateShares(2, groupConfigs,
            masterSecret, passphrase, 0);

        Assert.Throws<ArgumentException>(
            () => Slip39ShareCombination.CombineShares(allShares, passphrase));
    }

    [Fact]
    public void CombineShares_ExactThresholdFromEachGroup_Recovers()
    {
        var masterSecret = new byte[16];
        var passphrase = "test";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
        {
            new(2, 4), // Group 0: 2 of 4 shares
            new(3, 5)  // Group 1: 3 of 5 shares
        };

        var allShares = Slip39ShareGeneration.GenerateShares(2, groupConfigs,
            masterSecret, passphrase, 0);

        var exactly = allShares.Where(s => s.GroupIndex == 0).Take(2)
            .Concat(allShares.Where(s => s.GroupIndex == 1).Take(3))
            .ToList();

        var recovered = Slip39ShareCombination.CombineShares(exactly, passphrase);

        Assert.Equal(masterSecret, recovered);
    }
    
    [Fact]
    public void ValidateChecksums_ValidShares_ShouldNotThrow()
    {
        // This test used to generate shares, throw them away, and call ValidateChecksums on an
        // empty list — which passes without executing its loop body. It was parked behind a
        // comment saying share generation "doesn't yet calculate proper checksums"; that has
        // been true for some time now and nobody unparked it. The generated shares it already
        // built are what it should have been asserting on.
        var masterSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var passphrase = "test";
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(2, 3) };

        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs,
            masterSecret, passphrase, 0);

        Slip39ShareCombination.ValidateChecksums(shares);
    }

    [Fact]
    public void ValidateChecksums_CorruptedShare_ShouldThrow()
    {
        var masterSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(2, 3) };

        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs,
            masterSecret, "test", 0);

        // Alter a generated share so its stored checksum no longer covers its contents. The
        // companion test above only proves valid shares pass; without this one it would still
        // pass if ValidateChecksums accepted everything.
        var damaged = shares[0].ShareValue.ToArray();
        damaged[0] ^= 0xFF;

        var corrupted = new Slip39Share(
            shares[0].Identifier, shares[0].IsExtendable, shares[0].IterationExponent,
            shares[0].GroupIndex, shares[0].GroupThreshold, shares[0].GroupCount,
            shares[0].MemberIndex, shares[0].MemberThreshold, damaged, shares[0].Checksum);

        Assert.Throws<ArgumentException>(
            () => Slip39ShareCombination.ValidateChecksums(new List<Slip39Share> { corrupted }));
    }
    
    [Fact]
    public void ValidateChecksums_InvalidChecksum_ShouldThrow()
    {
        // Arrange - Create a share with an invalid checksum
        var share = new Slip39Share(
            identifier: 123,
            isExtendable: false,
            iterationExponent: 0,
            groupIndex: 0,
            groupThreshold: 0,
            groupCount: 0,
            memberIndex: 0,
            memberThreshold: 0,
            shareValue: new byte[16],
            checksum: 12345 // Invalid checksum
        );
        
        var shares = new List<Slip39Share> { share };
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareCombination.ValidateChecksums(shares));
    }
    
    [Fact]
    public void ValidateChecksums_EmptySharesList_ShouldNotThrow()
    {
        // Arrange
        var shares = new List<Slip39Share>();
        
        // Act & Assert - Should not throw
        Slip39ShareCombination.ValidateChecksums(shares);
    }
    
    [Fact]
    public void ShareToIndices_ValidShare_ProducesTheExpectedWordFormat()
    {
        // This used to reach into a private ConvertShareToWords by reflection. That method was
        // a copy of Slip39ShareParser.ShareToIndices, and the reflection made the duplicate
        // harder to delete than to keep. The copy is gone; this exercises the one encoder.
        var share = new Slip39Share(
            identifier: 0x1234,       // 15 bits
            isExtendable: true,       // 1 bit
            iterationExponent: 5,     // 4 bits
            groupIndex: 2,            // 4 bits
            groupThreshold: 1,        // 4 bits (encoded)
            groupCount: 2,            // 4 bits (encoded)
            memberIndex: 3,           // 4 bits
            memberThreshold: 1,       // 4 bits (encoded)
            shareValue: new byte[16], // 128 bits
            checksum: 0x12345678      // 30 bits
        );

        var indices = Slip39ShareParser.ShareToIndices(share);

        // 40 header + 128 value + 30 checksum = 198 bits, padded to 200 = 20 words.
        Assert.Equal(20, indices.Length);
        Assert.All(indices, i => Assert.InRange(i, 0, 1023));
    }

    [Fact]
    public void ValidateChecksums_AgreesWithTheEncoderUsedByToMnemonic()
    {
        // ValidateChecksums and ToMnemonic must encode a share identically; they now share
        // one implementation, and this is what would catch them drifting apart again.
        var masterSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(2, 3) };

        var shares = Slip39ShareGeneration.GenerateShares(1, groupConfigs, masterSecret, "test", 0);

        foreach (var share in shares)
        {
            Slip39ShareCombination.ValidateChecksums(new List<Slip39Share> { share });

            // The same share must survive a round trip through its mnemonic form unchanged.
            var reparsed = Slip39ShareParser.ParseFromMnemonic(share.ToMnemonic());
            Assert.Equal(share.Checksum, reparsed.Checksum);
            Assert.Equal(share.ShareValue, reparsed.ShareValue);
        }
    }
}
