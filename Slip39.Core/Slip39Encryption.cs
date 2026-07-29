using System.Security.Cryptography;
using System.Text;

namespace Slip39.Core;

/// <summary>
/// Implements the SLIP-0039 master secret encryption and decryption algorithms.
/// Uses a four-round Feistel network with PBKDF2 as the round function.
/// Reimplemented based on JS reference implementation.
/// </summary>
public static class Slip39Encryption
{
    private const int ROUND_COUNT = 4;
    private const int BASE_ITERATION_COUNT = 10000;

    // Feistel round indices, ascending for encryption and descending for decryption.
    // Crypt only enumerates the array it is handed and never writes to it, so both
    // directions share a single instance instead of allocating one per call.
    private static readonly byte[] EncryptRoundIndices = { 0, 1, 2, 3 };
    private static readonly byte[] DecryptRoundIndices = { 3, 2, 1, 0 };

    /// <summary>
    /// Encrypts a master secret using the SLIP-0039 encryption algorithm.
    /// </summary>
    /// <param name="masterSecret">The master secret to encrypt</param>
    /// <param name="passphrase">The passphrase for encryption (null or empty means no passphrase, i.e. the empty string)</param>
    /// <param name="iterationExponent">The iteration exponent (e)</param>
    /// <param name="identifier">The random identifier (id)</param>
    /// <param name="isExtendable">The extendable backup flag</param>
    /// <returns>The encrypted master secret</returns>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid</exception>
    public static byte[] Encrypt(byte[] masterSecret, string? passphrase, byte iterationExponent, 
        ushort identifier, bool isExtendable)
    {
        // Validate arguments
        if (masterSecret == null)
            throw new ArgumentNullException(nameof(masterSecret));
        if (masterSecret.Length < 16)
            throw new ArgumentException("Master secret must be at least 16 bytes", nameof(masterSecret));
        if (masterSecret.Length % 2 != 0)
            throw new ArgumentException("Master secret length must be even", nameof(masterSecret));
        if (iterationExponent > 15)
            throw new ArgumentException("Iteration exponent must be 4 bits or less", nameof(iterationExponent));
        if (identifier > 0x7FFF)
            throw new ArgumentException("Identifier must be 15 bits or less", nameof(identifier));
        
        return Crypt(identifier, iterationExponent, masterSecret, EncryptRoundIndices, passphrase, isExtendable);
    }
    
    /// <summary>
    /// Decrypts an encrypted master secret using the SLIP-0039 decryption algorithm.
    /// </summary>
    /// <param name="encryptedMasterSecret">The encrypted master secret to decrypt</param>
    /// <param name="passphrase">The passphrase for decryption (null or empty means no passphrase, i.e. the empty string)</param>
    /// <param name="iterationExponent">The iteration exponent (e)</param>
    /// <param name="identifier">The random identifier (id)</param>
    /// <param name="isExtendable">The extendable backup flag</param>
    /// <returns>The decrypted master secret</returns>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid</exception>
    public static byte[] Decrypt(byte[] encryptedMasterSecret, string? passphrase, byte iterationExponent,
        ushort identifier, bool isExtendable)
    {
        // Validate arguments
        if (encryptedMasterSecret == null)
            throw new ArgumentNullException(nameof(encryptedMasterSecret));
        if (encryptedMasterSecret.Length < 16)
            throw new ArgumentException("Encrypted master secret must be at least 16 bytes", nameof(encryptedMasterSecret));
        if (encryptedMasterSecret.Length % 2 != 0)
            throw new ArgumentException("Encrypted master secret length must be even", nameof(encryptedMasterSecret));
        if (iterationExponent > 15)
            throw new ArgumentException("Iteration exponent must be 4 bits or less", nameof(iterationExponent));
        if (identifier > 0x7FFF)
            throw new ArgumentException("Identifier must be 15 bits or less", nameof(identifier));
        
        return Crypt(identifier, iterationExponent, encryptedMasterSecret, DecryptRoundIndices, passphrase, isExtendable);
    }
    
    /// <summary>
    /// Core Feistel network implementation matching reference.
    /// Intermediate half-buffers are zeroed as soon as they are no longer needed.
    /// </summary>
    /// <remarks>
    /// <paramref name="range"/> is one of the shared round-index arrays and must be treated as
    /// read-only: it carries no secret material, so it is neither modified nor zeroed here.
    /// </remarks>
    private static byte[] Crypt(int identifier, int iterationExponent, byte[] masterSecret, byte[] range, string? passphrase, bool extendable)
    {
        int len = masterSecret.Length / 2;
        byte[] left = new byte[len];
        byte[] right = new byte[len];
        
        Array.Copy(masterSecret, 0, left, 0, len);
        Array.Copy(masterSecret, len, right, 0, len);
        
        try
        {
            foreach (byte i in range)
            {
                byte[] f = Feistel(identifier, iterationExponent, i, right, passphrase, extendable);
                byte[] newRight = XorBytes(left, f);
                // Zero the Feistel output and the consumed left half immediately.
                CryptographicOperations.ZeroMemory(f);
                CryptographicOperations.ZeroMemory(left);
                // Advance: the current right becomes the next left.
                left = right;
                right = newRight;
            }
            
            // Return right || left  (final working buffers are copied first, then zeroed in finally)
            var result = new byte[masterSecret.Length];
            Array.Copy(right, 0, result, 0, len);
            Array.Copy(left, 0, result, len, len);
            return result;
        }
        finally
        {
            // Zero whatever left/right buffers still hold sensitive material.
            CryptographicOperations.ZeroMemory(left);
            CryptographicOperations.ZeroMemory(right);
        }
    }
    
    /// <summary>
    /// Feistel function matching reference implementation exactly.
    /// Sensitive intermediate buffers (key, passphrase bytes, salt) are zeroed before returning.
    /// Note: the returned byte[] is itself sensitive and is zeroed by the caller (Crypt).
    /// </summary>
    private static byte[] Feistel(int id, int iterationExponent, byte step, byte[] block, string? passphrase, bool extendable)
    {
        // Key = step || passphrase bytes (with Unicode normalization as per SLIP-0039 spec)
        var passphraseBytes = Slip39Passphrase.NormalizePassphrase(passphrase);
        byte[] key = ArrayConcat(new byte[] { step }, passphraseBytes);
        
        // Salt prefix = "shamir" + identifier bytes (or empty if extendable)
        byte[] saltPrefix = extendable ? Array.Empty<byte>() : ArrayConcat(Encoding.UTF8.GetBytes("shamir"), new byte[] { (byte)(id >> 8), (byte)(id & 0xff) });
        
        // Salt = saltPrefix || block  (block is a sensitive half of the working secret)
        byte[] salt = ArrayConcat(saltPrefix, block);
        
        // Iterations = (BASE_ITERATION_COUNT / ROUND_COUNT) << iterationExponent
        int iters = (BASE_ITERATION_COUNT / ROUND_COUNT) << iterationExponent;
        
        try
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(key, salt, iters, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(block.Length);
        }
        finally
        {
            // Zero sensitive intermediates.  The passphrase string itself is immutable
            // and cannot be cleared from the managed heap.
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(passphraseBytes);
            CryptographicOperations.ZeroMemory(salt);
            // For a non-extendable share the salt prefix holds only public data — the literal
            // shamir tag followed by the identifier bytes — but zero it anyway for consistency.
            // The Array.Empty singleton is shared process-wide and must not be written to.
            if (saltPrefix.Length > 0)
                CryptographicOperations.ZeroMemory(saltPrefix);
        }
    }
    
    
    /// <summary>
    /// Concatenate two arrays.
    /// </summary>
    private static T[] ArrayConcat<T>(T[] first, T[] second)
    {
        T[] result = new T[first.Length + second.Length];
        Array.Copy(first, 0, result, 0, first.Length);
        Array.Copy(second, 0, result, first.Length, second.Length);
        return result;
    }
    
    /// <summary>
    /// XOR two byte arrays of equal length.
    /// </summary>
    /// <param name="a">First byte array</param>
    /// <param name="b">Second byte array</param>
    /// <returns>XOR result</returns>
    /// <exception cref="ArgumentException">Thrown when arrays have different lengths</exception>
    private static byte[] XorBytes(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            throw new ArgumentException("Arrays must have the same length");
        
        var result = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
            result[i] = (byte)(a[i] ^ b[i]);
        
        return result;
    }
}
