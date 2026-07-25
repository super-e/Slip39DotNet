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
    /// Implements the "Combining the shares" algorithm from the specification.
    /// </summary>
    /// <param name="shares">List of shares to combine</param>
    /// <param name="passphrase">The passphrase for decryption</param>
    /// <returns>The recovered master secret</returns>
    /// <exception cref="ArgumentException">Thrown when shares are invalid</exception>
    /// <exception cref="InvalidOperationException">Thrown when combination fails</exception>
    public static byte[] CombineShares(List<Slip39Share> shares, string passphrase)
    {
        if (shares == null)
            throw new ArgumentNullException(nameof(shares));
        
        if (passphrase == null)
            throw new ArgumentNullException(nameof(passphrase));
        
        if (shares.Count == 0)
            throw new ArgumentException("At least one share is required");
        
        // Step 1: Validate shares using the comprehensive validation
        Slip39ShareCombination.ValidateShares(shares);
        
        // Get common parameters from first share
        var firstShare = shares[0];
        ushort identifier = firstShare.Identifier;
        bool isExtendable = firstShare.IsExtendable;
        byte iterationExponent = firstShare.IterationExponent;
        int groupThreshold = firstShare.ActualGroupThreshold;
        int groupCount = firstShare.ActualGroupCount;
        
        // Group shares by group index
        var sharesByGroup = shares.GroupBy(s => s.GroupIndex)
            .ToDictionary(g => g.Key, g => g.ToList());
        
        // Verify we have enough groups
        if (sharesByGroup.Count < groupThreshold)
            throw new ArgumentException($"Insufficient groups: need {groupThreshold}, got {sharesByGroup.Count}");
        
        // Step 2: Recover group shares
        var groupShareValues = new List<(byte index, byte[] value)>();
        
        foreach (var kvp in sharesByGroup)
        {
            byte groupIndex = kvp.Key;
            var groupShares = kvp.Value;
            
            // Verify we have enough member shares for this group
            int memberThreshold = groupShares[0].ActualMemberThreshold;
            if (groupShares.Count < memberThreshold)
                throw new ArgumentException($"Insufficient member shares for group {groupIndex}: need {memberThreshold}, got {groupShares.Count}");
            
            // Convert to member share format for recovery
            var memberShareValues = groupShares.Take(memberThreshold)
                .Select(s => (s.MemberIndex, s.ShareValue))
                .ToList();
            
            // Recover the group share
            byte[] groupShareValue = PolynomialInterpolation.RecoverSecret(memberThreshold, memberShareValues);
            groupShareValues.Add((groupIndex, groupShareValue));
        }
        
        // Step 3: Recover the encrypted master secret
        byte[] encryptedMasterSecret = PolynomialInterpolation.RecoverSecret(groupThreshold, 
            groupShareValues.Take(groupThreshold).ToList());
        
        // Step 4: Decrypt the master secret
        byte[] masterSecret = Slip39Encryption.Decrypt(encryptedMasterSecret, passphrase, 
            iterationExponent, identifier, isExtendable);
        
        return masterSecret;
    }
    
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
    
    /// <summary>
    /// Validates shares for the CombineShares method according to SLIP-0039 specification.
    /// This method is deprecated - use Slip39ShareCombination.ValidateShares instead.
    /// </summary>
    [Obsolete("Use Slip39ShareCombination.ValidateShares instead")]
    private static void ValidateCombineShares(List<Slip39Share> shares)
    {
        if (shares.Count == 0)
            throw new ArgumentException("At least one share is required");
        
        var firstShare = shares[0];
        
        // All shares must have the same identifier, ext, e, GT, G and length
        foreach (var share in shares)
        {
            if (share.Identifier != firstShare.Identifier)
                throw new ArgumentException("All shares must have the same identifier");
            
            if (share.IsExtendable != firstShare.IsExtendable)
                throw new ArgumentException("All shares must have the same extendable flag");
            
            if (share.IterationExponent != firstShare.IterationExponent)
                throw new ArgumentException("All shares must have the same iteration exponent");
            
            if (share.GroupThreshold != firstShare.GroupThreshold)
                throw new ArgumentException("All shares must have the same group threshold");
            
            if (share.GroupCount != firstShare.GroupCount)
                throw new ArgumentException("All shares must have the same group count");
            
            if (share.ShareValue.Length != firstShare.ShareValue.Length)
                throw new ArgumentException("All shares must have the same length");
        }
        
        // Verify G >= GT
        if (firstShare.ActualGroupCount < firstShare.ActualGroupThreshold)
            throw new ArgumentException("Group count must be greater than or equal to group threshold");
        
        // Group shares by group index and validate
        var sharesByGroup = shares.GroupBy(s => s.GroupIndex)
            .ToDictionary(g => g.Key, g => g.ToList());
        
        foreach (var kvp in sharesByGroup)
        {
            var groupShares = kvp.Value;
            
            // All shares in the same group must have the same member threshold
            var firstGroupShare = groupShares[0];
            foreach (var share in groupShares)
            {
                if (share.MemberThreshold != firstGroupShare.MemberThreshold)
                    throw new ArgumentException("All shares in the same group must have the same member threshold");
            }
            
            // Member indices must be pairwise distinct
            var memberIndices = groupShares.Select(s => s.MemberIndex).ToList();
            if (memberIndices.Count != memberIndices.Distinct().Count())
                throw new ArgumentException("Member indices within a group must be pairwise distinct");
        }
        
        // Validate share value length requirements
        int shareValueLengthBits = firstShare.ShareValue.Length * 8;
        if (shareValueLengthBits < 128)
            throw new ArgumentException("Share value length must be at least 128 bits");
    }
}
