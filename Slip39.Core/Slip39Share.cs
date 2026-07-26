using System.Text.Json.Serialization;

namespace Slip39.Core;

/// <summary>
/// Represents a SLIP-0039 share containing all the fields defined in the specification.
/// This class can parse shares from mnemonic words and serialize to hex or JSON formats.
/// </summary>
public class Slip39Share
{
    // SLIP-0039 specification constants
    private const int MAX_IDENTIFIER = 0x7FFF; // 15 bits
    private const int MAX_4_BIT_VALUE = 15;     // 4 bits
    private const uint MAX_CHECKSUM = 0x3FFFFFFF; // 30 bits
    /// <summary>
    /// Random 15-bit identifier that is the same for all shares in a set.
    /// Used to verify that shares belong together.
    /// </summary>
    [JsonPropertyName("identifier")]
    public ushort Identifier { get; set; }

    /// <summary>
    /// Extendable backup flag (1 bit). Indicates that the identifier is used 
    /// as salt in the encryption of the master secret when ext = 0.
    /// </summary>
    [JsonPropertyName("extendable")]
    public bool IsExtendable { get; set; }

    /// <summary>
    /// Iteration exponent (4 bits). Indicates the total number of iterations 
    /// to be used in PBKDF2. The number of iterations is calculated as 10000×2^e.
    /// </summary>
    [JsonPropertyName("iterationExponent")]
    public byte IterationExponent { get; set; }

    /// <summary>
    /// Group index (4 bits). The x value of the group share.
    /// </summary>
    [JsonPropertyName("groupIndex")]
    public byte GroupIndex { get; set; }

    /// <summary>
    /// Group threshold (4 bits). Indicates how many group shares are needed 
    /// to reconstruct the master secret. The actual value is GT - 1.
    /// </summary>
    [JsonPropertyName("groupThreshold")]
    public byte GroupThreshold { get; set; }

    /// <summary>
    /// Group count (4 bits). The total number of groups. The actual value is G - 1.
    /// </summary>
    [JsonPropertyName("groupCount")]
    public byte GroupCount { get; set; }

    /// <summary>
    /// Member index (4 bits). The x value of the member share in the given group.
    /// </summary>
    [JsonPropertyName("memberIndex")]
    public byte MemberIndex { get; set; }

    /// <summary>
    /// Member threshold (4 bits). Indicates how many member shares are needed 
    /// to reconstruct the group share. The actual value is T - 1.
    /// </summary>
    [JsonPropertyName("memberThreshold")]
    public byte MemberThreshold { get; set; }

    /// <summary>
    /// Padded share value. This corresponds to the SSS part's f_k(x) values.
    /// The value is left-padded with "0" bits so that the length becomes 
    /// the nearest multiple of 10.
    /// </summary>
    [JsonPropertyName("shareValue")]
    public byte[] ShareValue { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// RS1024 checksum (30 bits) of the data part of the share.
    /// </summary>
    [JsonPropertyName("checksum")]
    public uint Checksum { get; set; }

    /// <summary>
    /// Gets the actual group threshold value (adds 1 to the encoded value).
    /// </summary>
    [JsonIgnore]
    public int ActualGroupThreshold => GroupThreshold + 1;

    /// <summary>
    /// Gets the actual group count value (adds 1 to the encoded value).
    /// </summary>
    [JsonIgnore]
    public int ActualGroupCount => GroupCount + 1;

    /// <summary>
    /// Gets the actual member threshold value (adds 1 to the encoded value).
    /// </summary>
    [JsonIgnore]
    public int ActualMemberThreshold => MemberThreshold + 1;

    /// <summary>
    /// Gets the total number of PBKDF2 iterations (10000 × 2^IterationExponent).
    /// </summary>
    [JsonIgnore]
    public int TotalIterations => 10000 * (1 << IterationExponent);

    /// <summary>
    /// Gets the customization string for RS1024 checksum based on the extendable flag.
    /// </summary>
    [JsonIgnore]
    public string ChecksumCustomizationString => IsExtendable ? "shamir_extendable" : "shamir";

    /// <summary>
    /// Creates a new empty SLIP-0039 share.
    /// </summary>
    public Slip39Share()
    {
    }

    /// <summary>
    /// Creates a new SLIP-0039 share with the specified parameters.
    /// </summary>
    /// <param name="identifier">15-bit identifier</param>
    /// <param name="isExtendable">Extendable backup flag</param>
    /// <param name="iterationExponent">Iteration exponent (0-15)</param>
    /// <param name="groupIndex">Group index (0-15)</param>
    /// <param name="groupThreshold">Group threshold - 1 (0-15)</param>
    /// <param name="groupCount">Group count - 1 (0-15)</param>
    /// <param name="memberIndex">Member index (0-15)</param>
    /// <param name="memberThreshold">Member threshold - 1 (0-15)</param>
    /// <param name="shareValue">Share value bytes</param>
    /// <param name="checksum">30-bit checksum</param>
    public Slip39Share(ushort identifier, bool isExtendable, byte iterationExponent,
        byte groupIndex, byte groupThreshold, byte groupCount,
        byte memberIndex, byte memberThreshold, byte[] shareValue, uint checksum)
    {
        ValidateFieldRanges(identifier, iterationExponent, groupIndex, groupThreshold,
            groupCount, memberIndex, memberThreshold, checksum);

        Identifier = identifier;
        IsExtendable = isExtendable;
        IterationExponent = iterationExponent;
        GroupIndex = groupIndex;
        GroupThreshold = groupThreshold;
        GroupCount = groupCount;
        MemberIndex = memberIndex;
        MemberThreshold = memberThreshold;
        ShareValue = shareValue ?? throw new ArgumentNullException(nameof(shareValue));
        Checksum = checksum;
    }

    /// <summary>
    /// Validates that all field values are within their specified bit ranges.
    /// </summary>
    private static void ValidateFieldRanges(ushort identifier, byte iterationExponent,
        byte groupIndex, byte groupThreshold, byte groupCount,
        byte memberIndex, byte memberThreshold, uint checksum)
    {
        if (identifier > 0x7FFF) // 15 bits
            throw new ArgumentOutOfRangeException(nameof(identifier), "Identifier must be 15 bits or less");
        
        if (iterationExponent > 15) // 4 bits
            throw new ArgumentOutOfRangeException(nameof(iterationExponent), "Iteration exponent must be 4 bits or less");
        
        if (groupIndex > 15) // 4 bits
            throw new ArgumentOutOfRangeException(nameof(groupIndex), "Group index must be 4 bits or less");
        
        if (groupThreshold > 15) // 4 bits
            throw new ArgumentOutOfRangeException(nameof(groupThreshold), "Group threshold must be 4 bits or less");
        
        if (groupCount > 15) // 4 bits
            throw new ArgumentOutOfRangeException(nameof(groupCount), "Group count must be 4 bits or less");
        
        if (memberIndex > 15) // 4 bits
            throw new ArgumentOutOfRangeException(nameof(memberIndex), "Member index must be 4 bits or less");
        
        if (memberThreshold > 15) // 4 bits
            throw new ArgumentOutOfRangeException(nameof(memberThreshold), "Member threshold must be 4 bits or less");
        
        if (checksum > 0x3FFFFFFF) // 30 bits
            throw new ArgumentOutOfRangeException(nameof(checksum), "Checksum must be 30 bits or less");
    }

    /// <summary>
    /// Converts the share to a mnemonic phrase using the SLIP-0039 wordlist.
    /// </summary>
    /// <returns>A mnemonic phrase as a space-separated string of words</returns>
    public string ToMnemonic()
    {
        var indices = Slip39ShareParser.ShareToIndices(this);
        var words = Wordlist.IndicesToWords(indices);
        return string.Join(" ", words);
    }

    /// <summary>
    /// Serializes the share to a hexadecimal string representation.
    /// The format is the canonical SLIP-0039 bit stream — identifier(15) + ext(1) + e(4) +
    /// GI(4) + Gt(4) + g(4) + I(4) + t(4) + padding + share value + C(30) — right-padded
    /// with zero bits to reach a byte boundary.
    /// </summary>
    /// <remarks>
    /// The bit stream is derived from <see cref="Slip39ShareParser.ShareToIndices"/>, the
    /// same source used by <see cref="ToMnemonic"/>, so the hex and mnemonic forms encode
    /// identical bits by construction. Deriving the layout independently here is what
    /// previously left the two out of step: the padding was appended instead of prepended,
    /// and <see cref="Slip39ShareParser.ParseFromHex"/> could not read back what this
    /// method wrote.
    /// </remarks>
    /// <returns>Hexadecimal string representation of the share</returns>
    public string ToHex()
    {
        var indices = Slip39ShareParser.ShareToIndices(this);

        var bits = new List<bool>(indices.Length * 10);
        foreach (var index in indices)
        {
            AddBits(bits, (uint)index, 10);
        }

        return BitsToHex(bits);
    }

    /// <summary>
    /// Adds bits of a value to the bit list in big-endian order.
    /// </summary>
    private static void AddBits(List<bool> bits, uint value, int bitCount)
    {
        for (int i = bitCount - 1; i >= 0; i--)
        {
            bits.Add((value & (1u << i)) != 0);
        }
    }

    /// <summary>
    /// Converts a list of bits to a hexadecimal string.
    /// </summary>
    private static string BitsToHex(List<bool> bits)
    {
        // Pad to byte boundary
        while (bits.Count % 8 != 0)
        {
            bits.Add(false);
        }
        
        var bytes = new byte[bits.Count / 8];
        for (int i = 0; i < bytes.Length; i++)
        {
            byte value = 0;
            for (int j = 0; j < 8; j++)
            {
                if (bits[i * 8 + j])
                {
                    value |= (byte)(1 << (7 - j));
                }
            }
            bytes[i] = value;
        }
        
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Returns a string representation of the share showing all field values.
    /// </summary>
    public override string ToString()
    {
        return $"Share(ID:{Identifier:X4}, Ext:{IsExtendable}, IterExp:{IterationExponent}, " +
               $"Group:{GroupIndex}/{ActualGroupCount} (need {ActualGroupThreshold}), " +
               $"Member:{MemberIndex} (need {ActualMemberThreshold}), " +
               $"Value:{ShareValue.Length} bytes, Checksum:{Checksum:X8})";
    }

    /// <summary>
    /// Checks if this share is compatible with another share for combination.
    /// Shares are compatible if they have the same identifier, extendable flag,
    /// iteration exponent, group threshold, and group count.
    /// </summary>
    /// <param name="other">The other share to check compatibility with</param>
    /// <returns>True if the shares are compatible, false otherwise</returns>
    public bool IsCompatibleWith(Slip39Share other)
    {
        if (other == null) return false;
        
        return Identifier == other.Identifier &&
               IsExtendable == other.IsExtendable &&
               IterationExponent == other.IterationExponent &&
               GroupThreshold == other.GroupThreshold &&
               GroupCount == other.GroupCount &&
               ShareValue.Length == other.ShareValue.Length;
    }

    /// <summary>
    /// Validates the logical consistency of the share fields.
    /// </summary>
    /// <returns>True if the share is logically valid, false otherwise</returns>
    public bool IsLogicallyValid()
    {
        // Group threshold must not exceed group count
        if (ActualGroupThreshold > ActualGroupCount) return false;
        
        // Share value must be at least 128 bits (16 bytes)
        if (ShareValue.Length < 16) return false;
        
        // Group and member indices must be within valid ranges
        if (GroupIndex >= ActualGroupCount) return false;
        
        return true;
    }
}
