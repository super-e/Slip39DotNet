using System.Security.Cryptography;

namespace Slip39.Core;

/// <summary>
/// Implements the SLIP-0039 share generation algorithms according to the specification.
/// </summary>
public static class Slip39ShareGeneration
{
    /// <summary>
    /// Represents the configuration for a group in the sharing scheme.
    /// </summary>
    public class GroupConfig
    {
        /// <summary>
        /// The threshold of shares needed to reconstruct the group secret.
        /// </summary>
        public int MemberThreshold { get; set; }
        
        /// <summary>
        /// The total number of shares to generate for this group.
        /// </summary>
        public int MemberCount { get; set; }
        
        /// <summary>
        /// Creates a new group configuration.
        /// </summary>
        /// <param name="memberThreshold">Threshold of shares needed</param>
        /// <param name="memberCount">Total number of shares to generate</param>
        public GroupConfig(int memberThreshold, int memberCount)
        {
            MemberThreshold = memberThreshold;
            MemberCount = memberCount;
        }
    }
    
    /// <summary>
    /// Generates SLIP-0039 shares according to the GenerateShares algorithm.
    /// </summary>
    /// <param name="groupThreshold">Number of groups needed to reconstruct the master secret</param>
    /// <param name="groupConfigs">Configuration for each group (thresholds and counts)</param>
    /// <param name="masterSecret">The master secret to share</param>
    /// <param name="passphrase">The passphrase for encryption (null defaults to "TREZOR")</param>
    /// <param name="iterationExponent">The iteration exponent (e)</param>
    /// <param name="isExtendable">Whether to generate extendable shares (affects encryption and checksum)</param>
    /// <returns>List of generated shares</returns>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid</exception>
    public static List<Slip39Share> GenerateShares(int groupThreshold, List<GroupConfig> groupConfigs,
        byte[] masterSecret, string? passphrase, byte iterationExponent, bool isExtendable = true)
    {
        if (groupConfigs == null)
            throw new ArgumentNullException(nameof(groupConfigs));
        
        if (masterSecret == null)
            throw new ArgumentNullException(nameof(masterSecret));
        
        // Validate parameters
        ValidateGenerateSharesParameters(groupThreshold, groupConfigs, masterSecret, iterationExponent);
        
        // Step 1: Check that if Ti = 1 and Ni > 1 for any i, then abort
        foreach (var config in groupConfigs)
        {
            if (config.MemberThreshold == 1 && config.MemberCount > 1)
                throw new ArgumentException("If member threshold is 1, member count should also be 1");
        }
        
        // Step 2: Generate a random 15-bit value id
        using var rng = RandomNumberGenerator.Create();
        var idBytes = new byte[2];
        rng.GetBytes(idBytes);
        ushort identifier = (ushort)((idBytes[0] << 7) | (idBytes[1] >> 1)); // 15 bits
        
        // Step 3: Use the provided extendable flag
        // Note: isExtendable parameter is already defined above
        
        // Step 4: Compute the encrypted master secret EMS = Encrypt(MS, P, e, id, ext)
        byte[] encryptedMasterSecret = Slip39Encryption.Encrypt(masterSecret, passphrase, 
            iterationExponent, identifier, isExtendable);
        
        // Step 5: Compute the group shares s1, ..., sG = SplitSecret(GT, G, EMS)
        int groupCount = groupConfigs.Count;
        byte[][] groupShares = PolynomialInterpolation.SplitSecret(groupThreshold, groupCount, encryptedMasterSecret);
        
        // Step 6: For each group share si, compute the member shares
        var allShares = new List<Slip39Share>();
        
        for (int groupIndex = 0; groupIndex < groupCount; groupIndex++)
        {
            var config = groupConfigs[groupIndex];
            byte[] groupShare = groupShares[groupIndex];
            
            // Split the group share into member shares
            byte[][] memberShares = PolynomialInterpolation.SplitSecret(config.MemberThreshold, 
                config.MemberCount, groupShare);
            
            // Step 7: For each member share, create a Slip39Share object
            for (int memberIndex = 0; memberIndex < config.MemberCount; memberIndex++)
            {
                // Create temporary share to calculate checksum
                var tempShare = new Slip39Share(
                    identifier: identifier,
                    isExtendable: isExtendable,
                    iterationExponent: iterationExponent,
                    groupIndex: (byte)groupIndex,
                    groupThreshold: (byte)(groupThreshold - 1), // Encoded as GT - 1
                    groupCount: (byte)(groupCount - 1),         // Encoded as G - 1  
                    memberIndex: (byte)memberIndex,
                    memberThreshold: (byte)(config.MemberThreshold - 1), // Encoded as T - 1
                    shareValue: memberShares[memberIndex],
                    checksum: 0 // Temporary - will be calculated below
                );
                
                // Calculate the proper checksum
                uint calculatedChecksum = CalculateShareChecksum(tempShare);
                
                // Create the final share with the correct checksum
                var share = new Slip39Share(
                    identifier: identifier,
                    isExtendable: isExtendable,
                    iterationExponent: iterationExponent,
                    groupIndex: (byte)groupIndex,
                    groupThreshold: (byte)(groupThreshold - 1), // Encoded as GT - 1
                    groupCount: (byte)(groupCount - 1),         // Encoded as G - 1  
                    memberIndex: (byte)memberIndex,
                    memberThreshold: (byte)(config.MemberThreshold - 1), // Encoded as T - 1
                    shareValue: memberShares[memberIndex],
                    checksum: calculatedChecksum
                );
                
                allShares.Add(share);
            }
        }
        
        return allShares;
    }
    
    /// <summary>
    /// Combines SLIP-0039 shares to recover the master secret.
    /// </summary>
    /// <param name="shares">List of shares to combine</param>
    /// <param name="passphrase">The passphrase for decryption (null defaults to "TREZOR")</param>
    /// <returns>The recovered master secret</returns>
    /// <exception cref="ArgumentException">Thrown when shares are invalid</exception>
    /// <exception cref="InvalidOperationException">Thrown when combination fails</exception>
    /// <remarks>
    /// Retained only so existing callers keep compiling. This used to be a second, independent
    /// implementation of the same algorithm, and the two drifted apart: this one never received
    /// the key-material zeroing, iterated groups in Dictionary order rather than by group index,
    /// and rejected a null passphrase instead of applying the "TREZOR" default. Two public
    /// entry points for one operation differing in their security properties is a trap —
    /// whichever a caller reaches for first is the one they get. It now forwards, so there is
    /// one implementation to keep correct.
    /// </remarks>
    [Obsolete("Use Slip39ShareCombination.CombineShares instead. This overload forwards to it.")]
    public static byte[] CombineShares(List<Slip39Share> shares, string? passphrase)
        => Slip39ShareCombination.CombineShares(shares, passphrase);

    /// <summary>
    /// Calculates the proper checksum for a share according to SLIP-0039 specification.
    /// </summary>
    /// <param name="share">The share to calculate checksum for (checksum field is ignored)</param>
    /// <returns>The calculated 30-bit checksum value</returns>
    private static uint CalculateShareChecksum(Slip39Share share)
    {
        // Convert share to indices but extract only the data portion (without checksum)
        var allIndices = Slip39ShareParser.ShareToIndices(share);
        
        // The checksum is calculated over all words except the last 3 checksum words
        var dataIndices = new ushort[allIndices.Length - 3];
        for (int i = 0; i < dataIndices.Length; i++)
        {
            dataIndices[i] = (ushort)allIndices[i];
        }
        
        // Generate the 3-word checksum using RS1024
        var checksumWords = Rs1024Checksum.GenerateChecksum(dataIndices, share.IsExtendable);
        
        // Pack the 3 checksum words into a 30-bit value
        uint checksum = ((uint)checksumWords[0] << 20) | ((uint)checksumWords[1] << 10) | checksumWords[2];
        
        return checksum;
    }
    
    /// <summary>
    /// Validates parameters for the GenerateShares method.
    /// </summary>
    private static void ValidateGenerateSharesParameters(int groupThreshold, List<GroupConfig> groupConfigs,
        byte[] masterSecret, byte iterationExponent)
    {
        if (groupThreshold <= 0 || groupThreshold > 16)
            throw new ArgumentException("Group threshold must be between 1 and 16");
        
        if (groupConfigs.Count == 0)
            throw new ArgumentException("At least one group configuration is required");
        
        if (groupConfigs.Count > 16)
            throw new ArgumentException("Maximum 16 groups are allowed");
        
        if (groupThreshold > groupConfigs.Count)
            throw new ArgumentException("Group threshold cannot exceed the number of groups");
        
        if (iterationExponent > 15)
            throw new ArgumentException("Iteration exponent must be 4 bits or less");
        
        if (masterSecret.Length < 16 || masterSecret.Length % 2 != 0)
            throw new ArgumentException("Master secret length must be at least 128 bits and a multiple of 16 bits");
        
        // Validate each group configuration
        foreach (var config in groupConfigs)
        {
            if (config.MemberThreshold <= 0 || config.MemberThreshold > 16)
                throw new ArgumentException("Member threshold must be between 1 and 16");
            
            if (config.MemberCount <= 0 || config.MemberCount > 16)
                throw new ArgumentException("Member count must be between 1 and 16");
            
            if (config.MemberThreshold > config.MemberCount)
                throw new ArgumentException("Member threshold cannot exceed member count");
        }
    }
    
}
