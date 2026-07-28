using System.Text;
using Xunit;

namespace Slip39.Core.Tests;

/// <summary>
/// Debug tests to investigate BIP32 master key generation differences.
/// </summary>
public class Bip32DebugTests
{
    [Fact]
    public void DebugMasterKeyGeneration_FirstTestVector()
    {
        // Test vector 1: "Valid mnemonic without sharing (128 bits)"
        var mnemonic = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard";
        var expectedMasterKey = "xprv9s21ZrQH143K4QViKpwKCpS2zVbz8GrZgpEchMDg6KME9HZtjfL7iThE9w5muQA4YPHKN1u5VM1w8D4pvnjxa2BmpGMfXr7hnRrRHZ93awZ";
        
        Console.WriteLine($"=== Debug Master Key Generation ===");
        Console.WriteLine($"Mnemonic: {mnemonic}");
        Console.WriteLine($"Expected: {expectedMasterKey}");
        
        // Step 1: Parse and combine
        var result = Slip39.CombineMnemonics(new[] { mnemonic }, "TREZOR");
        
        if (result.IsSuccess)
        {
            Console.WriteLine($"Master Secret (hex): {Convert.ToHexString(result.MasterSecret).ToLowerInvariant()}");
            Console.WriteLine($"Master Secret length: {result.MasterSecret.Length} bytes");
            
            // Step 2: Generate master key
            var actualMasterKey = Slip39.GenerateMasterKey(result.MasterSecret);
            Console.WriteLine($"Actual:   {actualMasterKey}");
            
            // Step 3: Compare byte by byte after Base58Check decode
            try 
            {
                var expectedBytes = Base58Check.Decode(expectedMasterKey);
                var actualBytes = Base58Check.Decode(actualMasterKey);
                
                Console.WriteLine($"Expected bytes length: {expectedBytes.Length}");
                Console.WriteLine($"Actual bytes length:   {actualBytes.Length}");
                
                Console.WriteLine($"Expected bytes: {Convert.ToHexString(expectedBytes)}");
                Console.WriteLine($"Actual bytes:   {Convert.ToHexString(actualBytes)}");
                
                // Compare each field
                Console.WriteLine($"=== BIP32 Field Comparison ===");
                Console.WriteLine($"Version    - Expected: {Convert.ToHexString(expectedBytes[0..4])}, Actual: {Convert.ToHexString(actualBytes[0..4])}");
                Console.WriteLine($"Depth      - Expected: {expectedBytes[4]:X2}, Actual: {actualBytes[4]:X2}");
                Console.WriteLine($"Parent FP  - Expected: {Convert.ToHexString(expectedBytes[5..9])}, Actual: {Convert.ToHexString(actualBytes[5..9])}");
                Console.WriteLine($"Child Num  - Expected: {Convert.ToHexString(expectedBytes[9..13])}, Actual: {Convert.ToHexString(actualBytes[9..13])}");
                Console.WriteLine($"Chain Code - Expected: {Convert.ToHexString(expectedBytes[13..45])}, Actual: {Convert.ToHexString(actualBytes[13..45])}");
                Console.WriteLine($"Private Key- Expected: {Convert.ToHexString(expectedBytes[45..78])}, Actual: {Convert.ToHexString(actualBytes[45..78])}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error decoding Base58Check: {ex.Message}");
            }
        }
        else
        {
            Console.WriteLine($"Failed to combine: {result.ErrorMessage}");
        }
    }
    
    [Fact]
    public void DebugHmacSeedOptions()
    {
        // Test different HMAC seed options using actual recovered master secret
        var masterSecret = Convert.FromHexString("bb54aac4b89dc868ba37d9cc21b2cece");
        
        Console.WriteLine($"=== Testing Different HMAC Seeds ===");
        Console.WriteLine($"Master Secret: {Convert.ToHexString(masterSecret)}");
        
        var hmacSeeds = new[]
        {
            "ed25519 seed",
            "Symmetric key seed", 
            "Bitcoin seed",
            "mnemonic",
            "TREZOR",
            "slip39"
        };
        
        foreach (var seed in hmacSeeds)
        {
            using var hmac = new System.Security.Cryptography.HMACSHA512(Encoding.UTF8.GetBytes(seed));
            var hash = hmac.ComputeHash(masterSecret);
            var privateKey = hash[0..32];
            var chainCode = hash[32..64];
            
            Console.WriteLine($"HMAC seed '{seed}':");
            Console.WriteLine($"  Private Key: {Convert.ToHexString(privateKey)}");
            Console.WriteLine($"  Chain Code:  {Convert.ToHexString(chainCode)}");
            
            // Build extended key and encode
            var extendedKey = new byte[78];
            Array.Copy(new byte[] { 0x04, 0x88, 0xAD, 0xE4 }, 0, extendedKey, 0, 4); // version
            extendedKey[4] = 0x00; // depth
            Array.Clear(extendedKey, 5, 8); // parent fingerprint + child number
            Array.Copy(chainCode, 0, extendedKey, 13, 32); // chain code
            extendedKey[45] = 0x00; // private key prefix
            Array.Copy(privateKey, 0, extendedKey, 46, 32); // private key
            
            var xprv = Base58Check.Encode(extendedKey);
            Console.WriteLine($"  xprv: {xprv}");
            Console.WriteLine();
        }
    }
    
    [Fact]
    public void DebugSeedConstruction()
    {
        // Test different seed construction methods
        var masterSecret = Convert.FromHexString("1e696b81357b16098c631dff6d19fc1c87f5ba9fe2ee96672da3336e4b70fc3e");
        var passphrase = "TREZOR";
        
        Console.WriteLine($"=== Testing Different Seed Construction ===");
        Console.WriteLine($"Master Secret: {Convert.ToHexString(masterSecret)}");
        Console.WriteLine($"Passphrase: {passphrase}");
        
        // Option 1: Master secret only
        var seed1 = masterSecret;
        Console.WriteLine($"Seed 1 (master secret only): {Convert.ToHexString(seed1)}");
        
        // Option 2: Master secret + passphrase
        var passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
        var seed2 = new byte[masterSecret.Length + passphraseBytes.Length];
        Array.Copy(masterSecret, 0, seed2, 0, masterSecret.Length);
        Array.Copy(passphraseBytes, 0, seed2, masterSecret.Length, passphraseBytes.Length);
        Console.WriteLine($"Seed 2 (ms + passphrase): {Convert.ToHexString(seed2)}");
        
        // Option 3: Passphrase + master secret
        var seed3 = new byte[passphraseBytes.Length + masterSecret.Length];
        Array.Copy(passphraseBytes, 0, seed3, 0, passphraseBytes.Length);
        Array.Copy(masterSecret, 0, seed3, passphraseBytes.Length, masterSecret.Length);
        Console.WriteLine($"Seed 3 (passphrase + ms): {Convert.ToHexString(seed3)}");
        
        // Option 4: Normalized passphrase + master secret
        var normalizedPassphrase = Slip39Passphrase.NormalizePassphrase(passphrase);
        var seed4 = new byte[normalizedPassphrase.Length + masterSecret.Length];
        Array.Copy(normalizedPassphrase, 0, seed4, 0, normalizedPassphrase.Length);
        Array.Copy(masterSecret, 0, seed4, normalizedPassphrase.Length, masterSecret.Length);
        Console.WriteLine($"Seed 4 (norm pp + ms): {Convert.ToHexString(seed4)}");
        
        // Test with "ed25519 seed" HMAC
        using var hmac = new System.Security.Cryptography.HMACSHA512(Encoding.UTF8.GetBytes("ed25519 seed"));
        
        foreach (var (seed, name) in new[] { (seed1, "Seed 1"), (seed2, "Seed 2"), (seed3, "Seed 3"), (seed4, "Seed 4") })
        {
            var hash = hmac.ComputeHash(seed);
            var privateKey = hash[0..32];
            var chainCode = hash[32..64];
            
            Console.WriteLine($"{name} -> Private Key: {Convert.ToHexString(privateKey)[0..16]}...");
        }
    }
    
    [Fact]
    public void DebugExpectedMasterSecret()
    {
        // Check if we can reverse engineer the expected master secret
        var expectedMasterKey = "xprv9s21ZrQH143K4QViKpwKCpS2zVbz8GrZgpEchVjZCnhE2qnpfHTQ5L9nVJRJgfE6qkS8DGLB5u5MWZfqPjJjUqm6BSTD4dXN7beBQHMxGY9";
        
        try
        {
            var expectedBytes = Base58Check.Decode(expectedMasterKey);
            var expectedPrivateKey = expectedBytes[46..78];
            var expectedChainCode = expectedBytes[13..45];
            
            Console.WriteLine($"=== Expected BIP32 Key Analysis ===");
            Console.WriteLine($"Expected Private Key: {Convert.ToHexString(expectedPrivateKey)}");
            Console.WriteLine($"Expected Chain Code:  {Convert.ToHexString(expectedChainCode)}");
            
            // Reconstruct the 64-byte hash that would generate these values
            var reconstructedHash = new byte[64];
            Array.Copy(expectedPrivateKey, 0, reconstructedHash, 0, 32);
            Array.Copy(expectedChainCode, 0, reconstructedHash, 32, 32);
            
            Console.WriteLine($"Reconstructed Hash: {Convert.ToHexString(reconstructedHash)}");
            
            // What seed would produce this hash with "ed25519 seed"?
            // This is computationally infeasible to reverse, but we can see the pattern
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
