using Xunit;

namespace Slip39.Core.Tests;

/// <summary>
/// Tests for SLIP-0039 encryption and decryption functionality.
/// </summary>
public class Slip39EncryptionTests
{
    [Fact]
    public void Encrypt_BasicScenario_ShouldSucceed()
    {
        // Arrange
        var masterSecret = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        var passphrase = "test passphrase";
        byte iterationExponent = 0;
        ushort identifier = 0x1234;
        bool isExtendable = true;

        // Act
        var encrypted = Slip39Encryption.Encrypt(masterSecret, passphrase, iterationExponent, 
            identifier, isExtendable);

        // Assert
        Assert.Equal(masterSecret.Length, encrypted.Length);
        Assert.NotEqual(masterSecret, encrypted); // Should be different after encryption
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip_ShouldRecoverOriginalSecret()
    {
        // Arrange
        var masterSecret = new byte[32]; // 256-bit secret
        for (int i = 0; i < masterSecret.Length; i++)
            masterSecret[i] = (byte)(i + 1);
        
        var passphrase = "test passphrase 123";
        byte iterationExponent = 2;
        ushort identifier = 0x7FFF; // Maximum 15-bit value
        bool isExtendable = false;

        // Act
        var encrypted = Slip39Encryption.Encrypt(masterSecret, passphrase, iterationExponent, 
            identifier, isExtendable);
        
        var decrypted = Slip39Encryption.Decrypt(encrypted, passphrase, iterationExponent,
            identifier, isExtendable);

        // Assert
        Assert.Equal(masterSecret, decrypted);
    }

    [Fact]
    public void Encrypt_DifferentPassphrases_ShouldProduceDifferentResults()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase1 = "passphrase 1";
        var passphrase2 = "passphrase 2";
        byte iterationExponent = 0;
        ushort identifier = 0x1000;
        bool isExtendable = true;

        // Act
        var encrypted1 = Slip39Encryption.Encrypt(masterSecret, passphrase1, iterationExponent, 
            identifier, isExtendable);
        
        var encrypted2 = Slip39Encryption.Encrypt(masterSecret, passphrase2, iterationExponent,
            identifier, isExtendable);

        // Assert
        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    public void Encrypt_DifferentIdentifiers_ShouldProduceDifferentResults()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test passphrase";
        byte iterationExponent = 0;
        ushort identifier1 = 0x1000;
        ushort identifier2 = 0x2000;
        bool isExtendable = false; // Use non-extendable mode so identifier affects salt

        // Act
        var encrypted1 = Slip39Encryption.Encrypt(masterSecret, passphrase, iterationExponent, 
            identifier1, isExtendable);
        
        var encrypted2 = Slip39Encryption.Encrypt(masterSecret, passphrase, iterationExponent,
            identifier2, isExtendable);

        // Assert
        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    public void Encrypt_ExtendableVsNonExtendable_ShouldProduceDifferentResults()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test passphrase";
        byte iterationExponent = 0;
        ushort identifier = 0x1000;

        // Act
        var encryptedExtendable = Slip39Encryption.Encrypt(masterSecret, passphrase, 
            iterationExponent, identifier, true);
        
        var encryptedNonExtendable = Slip39Encryption.Encrypt(masterSecret, passphrase,
            iterationExponent, identifier, false);

        // Assert
        Assert.NotEqual(encryptedExtendable, encryptedNonExtendable);
    }

    [Fact]
    public void Encrypt_DifferentIterationExponents_ShouldProduceDifferentResults()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test passphrase";
        ushort identifier = 0x1000;
        bool isExtendable = true;

        // Act
        var encrypted0 = Slip39Encryption.Encrypt(masterSecret, passphrase, 0, identifier, isExtendable);
        var encrypted1 = Slip39Encryption.Encrypt(masterSecret, passphrase, 1, identifier, isExtendable);

        // Assert
        Assert.NotEqual(encrypted0, encrypted1);
    }

    [Theory]
    [InlineData(16)]  // 128-bit
    [InlineData(32)]  // 256-bit
    [InlineData(64)]  // 512-bit
    public void EncryptDecrypt_VariousSecretLengths_ShouldWork(int secretLength)
    {
        // Arrange
        var masterSecret = new byte[secretLength];
        for (int i = 0; i < secretLength; i++)
            masterSecret[i] = (byte)(i % 256);
        
        var passphrase = "test";
        byte iterationExponent = 1;
        ushort identifier = 0x5555;
        bool isExtendable = true;

        // Act
        var encrypted = Slip39Encryption.Encrypt(masterSecret, passphrase, iterationExponent, 
            identifier, isExtendable);
        
        var decrypted = Slip39Encryption.Decrypt(encrypted, passphrase, iterationExponent,
            identifier, isExtendable);

        // Assert
        Assert.Equal(secretLength, encrypted.Length);
        Assert.Equal(masterSecret, decrypted);
    }

    [Fact]
    public void Encrypt_EmptyPassphrase_MeansNoPassphrase()
    {
        // Arrange
        var masterSecret = new byte[16];
        byte iterationExponent = 0;
        ushort identifier = 0x1000;
        bool isExtendable = true;

        // Act
        var encrypted = Slip39Encryption.Encrypt(masterSecret, "", iterationExponent,
            identifier, isExtendable);

        // Assert - null, empty and an explicitly empty passphrase are the same thing, and
        // none of them is "TREZOR". This test used to assert that "" decrypted with "TREZOR".
        Assert.Equal(masterSecret,
            Slip39Encryption.Decrypt(encrypted, null, iterationExponent, identifier, isExtendable));
        Assert.NotEqual(masterSecret,
            Slip39Encryption.Decrypt(encrypted, "TREZOR", iterationExponent, identifier, isExtendable));
    }

    [Fact]
    public void Decrypt_WrongPassphrase_ShouldNotRecoverCorrectSecret()
    {
        // Arrange
        var masterSecret = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        var correctPassphrase = "correct passphrase";
        var wrongPassphrase = "wrong passphrase";
        byte iterationExponent = 0;
        ushort identifier = 0x1000;
        bool isExtendable = true;

        var encrypted = Slip39Encryption.Encrypt(masterSecret, correctPassphrase, 
            iterationExponent, identifier, isExtendable);

        // Act
        var decryptedWithWrongPassphrase = Slip39Encryption.Decrypt(encrypted, wrongPassphrase,
            iterationExponent, identifier, isExtendable);

        // Assert
        Assert.NotEqual(masterSecret, decryptedWithWrongPassphrase);
    }

    [Fact]
    public void Encrypt_InvalidMasterSecretLength_ShouldThrow()
    {
        // Arrange
        var shortSecret = new byte[15]; // Less than 16 bytes
        var oddLengthSecret = new byte[17]; // Odd length
        var passphrase = "test";
        byte iterationExponent = 0;
        ushort identifier = 0x1000;
        bool isExtendable = true;

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39Encryption.Encrypt(shortSecret, passphrase, 
            iterationExponent, identifier, isExtendable));
        
        Assert.Throws<ArgumentException>(() => Slip39Encryption.Encrypt(oddLengthSecret, passphrase,
            iterationExponent, identifier, isExtendable));
    }

    [Fact]
    public void Encrypt_InvalidIterationExponent_ShouldThrow()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test";
        byte invalidIterationExponent = 16; // More than 4 bits
        ushort identifier = 0x1000;
        bool isExtendable = true;

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39Encryption.Encrypt(masterSecret, passphrase, 
            invalidIterationExponent, identifier, isExtendable));
    }

    [Fact]
    public void Encrypt_InvalidIdentifier_ShouldThrow()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test";
        byte iterationExponent = 0;
        ushort invalidIdentifier = 0x8000; // More than 15 bits
        bool isExtendable = true;

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39Encryption.Encrypt(masterSecret, passphrase, 
            iterationExponent, invalidIdentifier, isExtendable));
    }

    [Fact]
    public void Encrypt_NullArguments_ShouldThrow()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test";
        byte iterationExponent = 0;
        ushort identifier = 0x1000;
        bool isExtendable = true;

        // Act  Assert
        Assert.Throws<ArgumentNullException>(() => Slip39Encryption.Encrypt(null!, passphrase, 
            iterationExponent, identifier, isExtendable));
    }

    [Theory]
    [InlineData(0)]   // Minimum iterations: 2500 * 2^0 = 2500
    [InlineData(1)]   // 2500 * 2^1 = 5000
    [InlineData(10)]  // 2500 * 2^10 = 2,560,000
    [InlineData(15)]  // Maximum: 2500 * 2^15 = 81,920,000
    public void EncryptDecrypt_AllIterationExponents_ShouldWork(byte iterationExponent)
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test";
        ushort identifier = 0x1000;
        bool isExtendable = true;

        // Act
        var encrypted = Slip39Encryption.Encrypt(masterSecret, passphrase, iterationExponent, 
            identifier, isExtendable);
        
        var decrypted = Slip39Encryption.Decrypt(encrypted, passphrase, iterationExponent,
            identifier, isExtendable);

        // Assert
        Assert.Equal(masterSecret, decrypted);
    }

    [Fact]
    public void Encrypt_IdentifierAt15BitBoundary_ShouldWork()
    {
        // Arrange
        var masterSecret = new byte[16];
        var passphrase = "test";
        byte iterationExponent = 0;
        bool isExtendable = false; // Use non-extendable to test identifier in salt

        // Test boundary values for 15-bit identifier
        ushort[] testIdentifiers = { 0x0000, 0x0001, 0x7FFE, 0x7FFF };

        foreach (var identifier in testIdentifiers)
        {
            // Act
            var encrypted = Slip39Encryption.Encrypt(masterSecret, passphrase, iterationExponent, 
                identifier, isExtendable);
            
            var decrypted = Slip39Encryption.Decrypt(encrypted, passphrase, iterationExponent,
                identifier, isExtendable);

            // Assert
            Assert.Equal(masterSecret, decrypted);
        }
    }
}
