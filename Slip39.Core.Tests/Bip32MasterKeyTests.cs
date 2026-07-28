using System.Text;
using Xunit;

namespace Slip39.Core.Tests;

/// <summary>
/// Unit tests for BIP32 master key derivation and Base58Check encoding.
/// </summary>
public class Bip32MasterKeyTests
{
    [Fact]
    public void GenerateMasterKey_ValidMasterSecret_ShouldReturnValidXprv()
    {
        // Arrange
        var masterSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var passphrase = "TREZOR";

        // Act
        var result = Bip32MasterKey.GenerateMasterKey(masterSecret);

        // Assert
        Assert.NotNull(result);
        Assert.StartsWith("xprv", result);
        Assert.True(result.Length >= 100 && result.Length <= 120); // Typical xprv length
    }

    [Fact]
    public void GenerateMasterKey_ObsoleteOverload_IgnoresItsPassphrase()
    {
        // BIP-32 derivation is HMAC-SHA512("Bitcoin seed", seed) and takes no passphrase. The
        // overload that accepts one has never used it, which is why it is obsolete: in
        // SLIP-0039 the passphrase is consumed earlier, decrypting the master secret. Three
        // tests used to assert this behaviour under names claiming a "TREZOR default"; the
        // behaviour is worth one test, stated plainly.
        var masterSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var expected = Bip32MasterKey.GenerateMasterKey(masterSecret);

#pragma warning disable CS0618 // Type or member is obsolete
        Assert.Equal(expected, Bip32MasterKey.GenerateMasterKey(masterSecret));
        Assert.Equal(expected, Bip32MasterKey.GenerateMasterKey(masterSecret));
        Assert.Equal(expected, Bip32MasterKey.GenerateMasterKey(masterSecret));
        Assert.Equal(expected, Bip32MasterKey.GenerateMasterKey(masterSecret, "different"));
#pragma warning restore CS0618
    }

    [Fact]
    public void GenerateMasterKey_DifferentMasterSecrets_ShouldProduceDifferentKeys()
    {
        // Arrange
        var masterSecret1 = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var masterSecret2 = new byte[16] { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
        var passphrase = "TREZOR";

        // Act
        var result1 = Bip32MasterKey.GenerateMasterKey(masterSecret1);
        var result2 = Bip32MasterKey.GenerateMasterKey(masterSecret2);

        // Assert
        Assert.NotEqual(result1, result2);
    }

    [Fact]
    public void GenerateMasterKey_ConsistentResults_ShouldBeReproducible()
    {
        // Arrange
        var masterSecret = new byte[32] { 
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
        };
        var passphrase = "test passphrase";

        // Act
        var result1 = Bip32MasterKey.GenerateMasterKey(masterSecret);
        var result2 = Bip32MasterKey.GenerateMasterKey(masterSecret);

        // Assert
        Assert.Equal(result1, result2); // Should be deterministic
    }

    [Fact]
    public void GenerateMasterKey_NullMasterSecret_ShouldThrow()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => 
            Bip32MasterKey.GenerateMasterKey(null!));
    }

    [Fact]
    public void Base58Check_EncodeDecodeRoundTrip_ShouldRecoverOriginalData()
    {
        // Arrange
        var originalData = new byte[78]; // BIP32 extended key length
        for (int i = 0; i < originalData.Length; i++)
            originalData[i] = (byte)(i % 256);

        // Act
        var encoded = Base58Check.Encode(originalData);
        var decoded = Base58Check.Decode(encoded);

        // Assert
        Assert.Equal(originalData, decoded);
    }

    [Fact]
    public void Base58Check_Encode_KnownValue_ShouldProduceExpectedResult()
    {
        // Arrange - Test vector: empty byte array should encode to "1"
        var data = new byte[1] { 0 };

        // Act
        var result = Base58Check.Encode(data);

        // Assert
        Assert.StartsWith("1", result); // Leading zeros become '1's in Base58
    }

    [Fact]
    public void Base58Check_Decode_InvalidChecksum_ShouldThrow()
    {
        // Arrange - Create a valid encoding and then corrupt it
        var originalData = new byte[4] { 1, 2, 3, 4 };
        var validEncoding = Base58Check.Encode(originalData);
        var corruptedEncoding = validEncoding.Substring(0, validEncoding.Length - 1) + "Z";

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Base58Check.Decode(corruptedEncoding));
    }

    [Fact]
    public void Base58Check_Decode_InvalidCharacter_ShouldThrow()
    {
        // Arrange - Use character not in Base58 alphabet
        var invalidEncoding = "InvalidChar0";

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Base58Check.Decode(invalidEncoding));
    }

    [Fact]
    public void Base58Check_Encode_NullData_ShouldThrow()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Base58Check.Encode(null!));
    }

    [Fact]
    public void Base58Check_Decode_NullString_ShouldThrow()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Base58Check.Decode(null!));
    }

    [Fact]
    public void Base58Check_Decode_EmptyString_ShouldThrow()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Base58Check.Decode(""));
    }

    [Theory]
    [InlineData(16)]   // 128-bit
    [InlineData(32)]   // 256-bit
    [InlineData(64)]   // 512-bit
    public void GenerateMasterKey_VariousMasterSecretLengths_ShouldWork(int secretLength)
    {
        // Arrange
        var masterSecret = new byte[secretLength];
        for (int i = 0; i < secretLength; i++)
            masterSecret[i] = (byte)(i % 256);

        // Act
        var result = Bip32MasterKey.GenerateMasterKey(masterSecret);

        // Assert
        Assert.NotNull(result);
        Assert.StartsWith("xprv", result);
        
        // Should be able to decode the result
        var decoded = Base58Check.Decode(result);
        Assert.Equal(78, decoded.Length); // BIP32 extended key is always 78 bytes
    }



    [Fact]
    public void XprivRoundTrip_SplitAndCombine_ShouldRecoverOriginalKey()
    {
        // Arrange - Use a known test xpriv key
        var originalXpriv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        var passphrase = "TREZOR";
        
        // Act 1: Split the xpriv into SLIP-0039 shares
        var extendedKeyData = Base58Check.Decode(originalXpriv);
        
        // Extract private key and chain code
        var privateKey = new byte[32];
        var chainCode = new byte[32];
        Array.Copy(extendedKeyData, 46, privateKey, 0, 32); // Private key at offset 46
        Array.Copy(extendedKeyData, 13, chainCode, 0, 32);  // Chain code at offset 13
        
        // Combine into 64-byte secret
        var masterSecret = new byte[64];
        Array.Copy(privateKey, 0, masterSecret, 0, 32);
        Array.Copy(chainCode, 0, masterSecret, 32, 32);
        
        // Generate shares
        var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(2, 3) };
        var shares = Slip39ShareGeneration.GenerateShares(
            groupThreshold: 1,
            groupConfigs: groupConfigs,
            masterSecret: masterSecret,
            passphrase: passphrase,
            iterationExponent: 0,
            isExtendable: false);
        
        // Act 2: Combine the shares to recover the secret
        var sharesForRecovery = shares.Take(2).ToList();
        var recoveredSecret = Slip39ShareCombination.CombineShares(sharesForRecovery, passphrase);
        
        // Act 3: Reconstruct the xpriv
        var recoveredPrivateKey = new byte[32];
        var recoveredChainCode = new byte[32];
        Array.Copy(recoveredSecret, 0, recoveredPrivateKey, 0, 32);
        Array.Copy(recoveredSecret, 32, recoveredChainCode, 0, 32);
        
        // Build BIP32 extended private key structure
        var reconstructedExtendedKey = new byte[78];
        int offset = 0;
        
        // Version (4 bytes): 0x0488ADE4 for mainnet private key
        var mainnetPrivateVersion = new byte[] { 0x04, 0x88, 0xAD, 0xE4 };
        Array.Copy(mainnetPrivateVersion, 0, reconstructedExtendedKey, offset, 4);
        offset += 4;
        
        // Depth (1 byte): 0x00 for master key
        reconstructedExtendedKey[offset] = 0x00;
        offset += 1;
        
        // Parent fingerprint (4 bytes): 0x00000000 for master key
        Array.Clear(reconstructedExtendedKey, offset, 4);
        offset += 4;
        
        // Child number (4 bytes): 0x00000000 for master key
        Array.Clear(reconstructedExtendedKey, offset, 4);
        offset += 4;
        
        // Chain code (32 bytes)
        Array.Copy(recoveredChainCode, 0, reconstructedExtendedKey, offset, 32);
        offset += 32;
        
        // Private key (33 bytes): 0x00 prefix + 32-byte private key
        reconstructedExtendedKey[offset] = 0x00; // Private key prefix
        offset += 1;
        Array.Copy(recoveredPrivateKey, 0, reconstructedExtendedKey, offset, 32);
        
        var reconstructedXpriv = Base58Check.Encode(reconstructedExtendedKey);
        
        // Assert
        Assert.Equal(originalXpriv, reconstructedXpriv);
        Assert.Equal(privateKey, recoveredPrivateKey);
        Assert.Equal(chainCode, recoveredChainCode);
        Assert.Equal(masterSecret, recoveredSecret);
    }
    
    [Fact]
    public void ReconstructFromComponents_ValidInput_ReturnsCorrectXpriv()
    {
        // Arrange - Test data: known private key and chain code that should produce a specific xprv
        var privateKey = Convert.FromHexString("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        var chainCode = Convert.FromHexString("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
        
        // Combine into 64-byte secret
        var combinedSecret = new byte[64];
        Array.Copy(privateKey, 0, combinedSecret, 0, 32);
        Array.Copy(chainCode, 0, combinedSecret, 32, 32);
        
        // Act
        string reconstructedXpriv = Bip32MasterKey.ReconstructFromComponents(combinedSecret);
        
        // Assert
        Assert.StartsWith("xprv", reconstructedXpriv);
        Assert.Equal(111, reconstructedXpriv.Length); // Standard BIP32 xprv length
        
        // Verify we can decode it back and get the same components
        byte[] decodedData = Base58Check.Decode(reconstructedXpriv);
        Assert.Equal(78, decodedData.Length);
        
        // Extract and verify private key
        var extractedPrivateKey = new byte[32];
        Array.Copy(decodedData, 46, extractedPrivateKey, 0, 32);
        Assert.Equal(privateKey, extractedPrivateKey);
        
        // Extract and verify chain code
        var extractedChainCode = new byte[32];
        Array.Copy(decodedData, 13, extractedChainCode, 0, 32);
        Assert.Equal(chainCode, extractedChainCode);
    }
    
    [Fact]
    public void ReconstructFromComponents_InvalidLength_ThrowsException()
    {
        // Arrange - Test with wrong length input
        var invalidSecret = new byte[32]; // Should be 64 bytes
        
        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => Bip32MasterKey.ReconstructFromComponents(invalidSecret));
        Assert.Contains("must be 64 bytes", ex.Message);
    }
    
    [Fact]
    public void ReconstructFromComponents_NullInput_ThrowsException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Bip32MasterKey.ReconstructFromComponents(null!));
    }
    
    [Fact]
    public void ReconstructFromComponents_RoundTrip_WithExistingXpriv()
    {
        // Arrange - Use the same test xpriv from the previous test
        var originalXpriv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        
        // Decode the xpriv to get the private key and chain code
        byte[] extendedKeyData = Base58Check.Decode(originalXpriv);
        
        // Extract private key (32 bytes starting at offset 46) and chain code (32 bytes starting at offset 13)
        var privateKey = new byte[32];
        var chainCode = new byte[32];
        Array.Copy(extendedKeyData, 46, privateKey, 0, 32);
        Array.Copy(extendedKeyData, 13, chainCode, 0, 32);
        
        // Combine into 64-byte secret
        var combinedSecret = new byte[64];
        Array.Copy(privateKey, 0, combinedSecret, 0, 32);
        Array.Copy(chainCode, 0, combinedSecret, 32, 32);
        
        // Act - Reconstruct the BIP32 xpriv using the new method
        string reconstructedXpriv = Bip32MasterKey.ReconstructFromComponents(combinedSecret);
        
        // Assert - Verify we get back the exact same xpriv
        Assert.Equal(originalXpriv, reconstructedXpriv);
    }
}
