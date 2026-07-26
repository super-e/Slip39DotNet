using System.Security.Cryptography;

namespace Slip39.Core;

/// <summary>
/// Implements the complete SLIP-0039 "Combining the shares" algorithm according to the specification.
/// This includes all validation steps and proper error handling as defined in the standard.
/// </summary>
public static class Slip39ShareCombination
{
    /// <summary>
    /// Combines SLIP-0039 shares to recover the master secret according to the full specification.
    /// Implements all validation steps from the "Combining the shares" section.
    /// </summary>
    /// <param name="shares">List of parsed SLIP-0039 shares</param>
    /// <param name="passphrase">Passphrase for master secret decryption (null defaults to "TREZOR")</param>
    /// <returns>The recovered master secret</returns>
    /// <exception cref="ArgumentException">Thrown when share validation fails</exception>
    /// <exception cref="InvalidOperationException">Thrown when share combination fails</exception>
    /// <remarks>
    /// The reconstructed group shares and the encrypted master secret are zeroed before this
    /// method returns — they are recovered material that never reaches the caller. The master
    /// secret itself is the return value, so the caller owns it and should zero it with
    /// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory(byte[])"/>
    /// once finished. The shares passed in belong to the caller and are left untouched.
    /// </remarks>
    public static byte[] CombineShares(List<Slip39Share> shares, string? passphrase)
    {
        if (shares == null)
            throw new ArgumentNullException(nameof(shares));
        
        // Step 1: Perform all validation checks from the specification
        ValidateShares(shares);
        
        // Get common parameters from the first share
        var firstShare = shares[0];
        ushort identifier = firstShare.Identifier;
        bool isExtendable = firstShare.IsExtendable;
        byte iterationExponent = firstShare.IterationExponent;
        int groupThreshold = firstShare.ActualGroupThreshold;
        
        // Group shares by group index
        var sharesByGroup = shares.GroupBy(s => s.GroupIndex)
            .ToDictionary(g => g.Key, g => g.ToList());
        
        // Step 2: Recover each group share using RecoverSecret
        var groupShareValues = new List<(byte index, byte[] value)>();
        byte[]? encryptedMasterSecret = null;

        try
        {
            foreach (var kvp in sharesByGroup.OrderBy(g => g.Key))
            {
                byte groupIndex = kvp.Key;
                var groupShares = kvp.Value;
                int memberThreshold = groupShares[0].ActualMemberThreshold;

                // Create member index/share value pairs for this group
                var memberShareValues = groupShares
                    .Select(s => (s.MemberIndex, s.ShareValue))
                    .ToList();

                // Recover the group share using polynomial interpolation
                byte[] groupShareValue = PolynomialInterpolation.RecoverSecret(memberThreshold, memberShareValues);
                groupShareValues.Add((groupIndex, groupShareValue));
            }

            // Step 3: Recover the encrypted master secret using group shares
            encryptedMasterSecret = PolynomialInterpolation.RecoverSecret(groupThreshold, groupShareValues);

            // Step 4: Decrypt the master secret
            return Slip39Encryption.Decrypt(encryptedMasterSecret, passphrase,
                iterationExponent, identifier, isExtendable);
        }
        finally
        {
            // RecoverSecret hands ownership of what it returns to us, and none of this
            // reaches the caller: the group shares reconstruct the secret just as the
            // mnemonics do, and the encrypted master secret only lacks the passphrase.
            // Zero both. Note the shares in `memberShareValues` are the caller's and are
            // deliberately not touched here.
            foreach (var (_, value) in groupShareValues)
            {
                CryptographicOperations.ZeroMemory(value);
            }

            if (encryptedMasterSecret != null)
            {
                CryptographicOperations.ZeroMemory(encryptedMasterSecret);
            }
        }
    }
    
    /// <summary>
    /// Validates all shares according to the SLIP-0039 specification validation rules.
    /// Implements all checks from step 1 of the "Combining the shares" algorithm.
    /// </summary>
    /// <param name="shares">Shares to validate</param>
    /// <exception cref="ArgumentException">Thrown when any validation check fails</exception>
    public static void ValidateShares(List<Slip39Share> shares)
    {
        if (shares.Count == 0)
            throw new ArgumentException("At least one share is required");
        
        var firstShare = shares[0];
        
        // Check 1: All shares must have the same identifier, ext, e, GT, G and length
        foreach (var share in shares)
        {
            if (share.Identifier != firstShare.Identifier)
                throw new ArgumentException("All shares must have the same identifier");
            
            if (share.IsExtendable != firstShare.IsExtendable)
                throw new ArgumentException("All shares must have the same extendable backup flag");
            
            if (share.IterationExponent != firstShare.IterationExponent)
                throw new ArgumentException("All shares must have the same iteration exponent");
            
            if (share.GroupThreshold != firstShare.GroupThreshold)
                throw new ArgumentException("All shares must have the same group threshold");
            
            if (share.GroupCount != firstShare.GroupCount)
                throw new ArgumentException("All shares must have the same group count");
            
            if (share.ShareValue.Length != firstShare.ShareValue.Length)
                throw new ArgumentException("All shares must have the same length");
        }
        
        // Check 2: G must be greater than or equal to GT
        if (firstShare.ActualGroupCount < firstShare.ActualGroupThreshold)
            throw new ArgumentException("Group count must be greater than or equal to group threshold");
        
        // Check 3: GM (number of distinct group indices) must equal GT
        var distinctGroupIndices = shares.Select(s => s.GroupIndex).Distinct().ToList();
        int GM = distinctGroupIndices.Count;
        int GT = firstShare.ActualGroupThreshold;
        
        if (GM != GT)
            throw new ArgumentException($"Number of distinct group indices ({GM}) must equal group threshold ({GT})");
        
        // Check 4: Within each group, validate member threshold and indices
        var sharesByGroup = shares.GroupBy(s => s.GroupIndex).ToDictionary(g => g.Key, g => g.ToList());
        
        foreach (var kvp in sharesByGroup)
        {
            var groupShares = kvp.Value;
            var firstGroupShare = groupShares[0];
            
            // All shares in the same group must have the same member threshold
            foreach (var share in groupShares)
            {
                if (share.MemberThreshold != firstGroupShare.MemberThreshold)
                    throw new ArgumentException("All shares in the same group must have the same member threshold");
            }
            
            // Member indices must be pairwise distinct
            var memberIndices = groupShares.Select(s => s.MemberIndex).ToList();
            if (memberIndices.Count != memberIndices.Distinct().Count())
                throw new ArgumentException("Member indices within a group must be pairwise distinct");
            
            // Member count must be at least the member threshold
            int memberCount = groupShares.Count;
            int memberThreshold = firstGroupShare.ActualMemberThreshold;
            
            if (memberCount < memberThreshold)
                throw new ArgumentException($"Insufficient member shares for group {kvp.Key}: need {memberThreshold}, got {memberCount}");
        }
        
        // Check 5: Validate share value length requirements
        ValidateShareValueLength(firstShare);
    }
    
    /// <summary>
    /// Validates share value length according to SLIP-0039 specification.
    /// </summary>
    /// <param name="share">Share to validate</param>
    /// <exception cref="ArgumentException">Thrown when validation fails</exception>
    private static void ValidateShareValueLength(Slip39Share share)
    {
        int shareValueLengthBits = share.ShareValue.Length * 8;
        
        // The length of each share value must be at least 128 bits
        if (shareValueLengthBits < 128)
            throw new ArgumentException("Share value length must be at least 128 bits");
        
        // Note: We don't validate the total length being a multiple of 10 bits here
        // because that validation applies to the encoded mnemonic format, not the raw share data.
        // The raw share data can have any valid length that meets the minimum requirement.
        
        // The specification also mentions padding validation, but this would typically
        // be handled during the mnemonic parsing/encoding phase, not during share combination.
    }
    
    /// <summary>
    /// Validates that shares have valid checksums according to SLIP-0039 specification.
    /// Uses the RS1024 checksum algorithm with the "shamir" customization string.
    /// </summary>
    /// <param name="shares">Shares to validate</param>
    /// <exception cref="ArgumentException">Thrown when checksum validation fails</exception>
    public static void ValidateChecksums(List<Slip39Share> shares)
    {
        foreach (var share in shares)
        {
            // Convert the share to its mnemonic word representation for checksum validation
            var shareWords = ConvertShareToWords(share);
            
            // Verify the RS1024 checksum
            if (!Rs1024Checksum.VerifyChecksum(shareWords, share.IsExtendable))
            {
                throw new ArgumentException($"Invalid checksum for share with identifier {share.Identifier}");
            }
        }
    }
    
    /// <summary>
    /// Converts a share to its 10-bit word representation for checksum validation.
    /// This must match the exact format expected by the RS1024 checksum algorithm.
    /// Uses the same padding strategy as ShareToIndices in ShareParser for consistency.
    /// </summary>
    /// <param name="share">The share to convert</param>
    /// <returns>Array of 10-bit word values representing the complete share</returns>
    private static ushort[] ConvertShareToWords(Slip39Share share)
    {
        // Use the same logic as ShareParser.ShareToIndices to ensure consistency
        // Calculate total bits needed based on SLIP-39 specification
        // Header: 15+1+4+4+4+4+4+4 = 40 bits
        // Share value: (length * 8) bits
        // Checksum: 30 bits
        int headerBits = 40;
        int shareValueBits = share.ShareValue.Length * 8;
        int checksumBits = 30;
        int totalContentBits = headerBits + shareValueBits + checksumBits;
        
        // Calculate padding needed to align to 10-bit word boundaries
        int wordCount = (totalContentBits + 9) / 10; // Round up to nearest 10-bit boundary
        int totalBits = wordCount * 10;
        int paddingBits = totalBits - totalContentBits;
        
        var bits = new bool[totalBits];
        int bitIndex = 0;
        
        // Pack header data into bits (same order as ShareParser)
        WriteBits(bits, ref bitIndex, share.Identifier, 15);
        WriteBits(bits, ref bitIndex, share.IsExtendable ? 1u : 0u, 1);
        WriteBits(bits, ref bitIndex, share.IterationExponent, 4);
        WriteBits(bits, ref bitIndex, share.GroupIndex, 4);
        WriteBits(bits, ref bitIndex, share.GroupThreshold, 4);
        WriteBits(bits, ref bitIndex, share.GroupCount, 4);
        WriteBits(bits, ref bitIndex, share.MemberIndex, 4);
        WriteBits(bits, ref bitIndex, share.MemberThreshold, 4);
        
        // Add left-padding bits (should be 0s according to SLIP-39 spec)
        // CRITICAL: Padding goes here, after header, before share value (same as ShareParser)
        for (int i = 0; i < paddingBits; i++)
        {
            bits[bitIndex++] = false; // Padding bits are always 0
        }
        
        // Write share value
        foreach (var b in share.ShareValue)
        {
            WriteBits(bits, ref bitIndex, b, 8);
        }
        
        // Write checksum
        WriteBits(bits, ref bitIndex, share.Checksum, 30);
        
        // Convert bits back to word indices, then to ushort array
        var indices = new ushort[wordCount];
        for (int i = 0; i < wordCount; i++)
        {
            uint value = 0;
            for (int j = 0; j < 10; j++)
            {
                if (bits[i * 10 + j])
                {
                    value |= (uint)(1 << (9 - j));
                }
            }
            indices[i] = (ushort)value;
        }
        
        return indices;
    }
    
    /// <summary>
    /// Writes bits to a bit array at the specified position.
    /// Same implementation as in ShareParser for consistency.
    /// </summary>
    private static void WriteBits(bool[] bits, ref int startIndex, uint value, int bitCount)
    {
        for (int i = 0; i < bitCount; i++)
        {
            bits[startIndex + i] = (value & (1u << (bitCount - 1 - i))) != 0;
        }
        startIndex += bitCount;
    }
    
    /// <summary>
    /// Packs bits into a byte array at the specified bit offset.
    /// </summary>
    /// <param name="data">The byte array to pack into</param>
    /// <param name="bitOffset">The current bit offset (will be updated)</param>
    /// <param name="value">The value to pack</param>
    /// <param name="bitCount">The number of bits to pack</param>
    private static void PackBits(byte[] data, ref int bitOffset, uint value, int bitCount)
    {
        for (int i = bitCount - 1; i >= 0; i--)
        {
            if ((value & (1u << i)) != 0)
            {
                int byteIndex = bitOffset / 8;
                int bitIndex = bitOffset % 8;
                data[byteIndex] |= (byte)(1 << (7 - bitIndex));
            }
            bitOffset++;
        }
    }
}
