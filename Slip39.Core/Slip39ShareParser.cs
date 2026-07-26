using System.Text.Json;

namespace Slip39.Core;

/// <summary>
/// Provides parsing functionality for SLIP-0039 shares from various formats.
/// Supports parsing from mnemonic words, hexadecimal strings, and JSON.
/// </summary>
public static class Slip39ShareParser
{
    /// <summary>
    /// Parses a SLIP-0039 share from a space-separated mnemonic string.
    /// </summary>
    /// <param name="mnemonic">Space-separated mnemonic words</param>
    /// <returns>Parsed Slip39Share object</returns>
    /// <exception cref="ArgumentException">Thrown when the mnemonic format is invalid</exception>
    public static Slip39Share ParseFromMnemonic(string mnemonic)
    {
        if (string.IsNullOrWhiteSpace(mnemonic))
            throw new ArgumentException("Mnemonic cannot be null or empty", nameof(mnemonic));

        var words = mnemonic.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return ParseFromMnemonicWords(words);
    }

    /// <summary>
    /// Parses a SLIP-0039 share from an array of mnemonic words.
    /// </summary>
    /// <param name="words">Array of mnemonic words</param>
    /// <returns>Parsed Slip39Share object</returns>
    /// <exception cref="ArgumentException">Thrown when the word format is invalid</exception>
    public static Slip39Share ParseFromMnemonicWords(string[] words)
    {
        if (words == null)
            throw new ArgumentNullException(nameof(words));

        // Validate word count - SLIP-0039 supports variable length mnemonics based on secret size
        // Minimum: 20 words for 128-bit secrets, but longer secrets (like 64-byte BIP32) require more words
        if (words.Length < 20)
            throw new ArgumentException($"Invalid mnemonic length. Expected at least 20 words, got {words.Length}", nameof(words));

        // Convert words to indices (this is a placeholder - actual implementation would need the wordlist)
        var indices = ConvertWordsToIndices(words);

        // Convert indices to bit array
        var bits = IndicesToBits(indices);

        // Parse the bit array into share fields
        return ParseFromBits(bits);
    }

    /// <summary>
    /// Parses a SLIP-0039 share from a hexadecimal string.
    /// </summary>
    /// <param name="hexString">Hexadecimal string representation</param>
    /// <returns>Parsed Slip39Share object</returns>
    /// <exception cref="ArgumentException">Thrown when the hex format is invalid</exception>
    public static Slip39Share ParseFromHex(string hexString)
    {
        if (string.IsNullOrWhiteSpace(hexString))
            throw new ArgumentException("Hex string cannot be null or empty", nameof(hexString));

        // Remove any whitespace and convert to uppercase for consistency
        hexString = hexString.Replace(" ", "").Replace("-", "").ToUpperInvariant();

        // Validate hex string
        if (hexString.Length % 2 != 0)
            throw new ArgumentException("Hex string must have an even number of characters", nameof(hexString));

        try
        {
            var bytes = Convert.FromHexString(hexString);
            var bits = BytesToBits(bytes);

            // The hex form carries the canonical 10-bit-per-word stream produced by
            // ShareToIndices, right-padded with zero bits to reach a byte boundary.
            // That trailing slack is always fewer than 8 bits — i.e. less than one
            // word — so flooring the bit count to a multiple of 10 recovers the exact
            // original stream. ParseFromBits requires that multiple-of-10 length.
            int wordCount = bits.Length / 10;
            Array.Resize(ref bits, wordCount * 10);

            return ParseFromBits(bits);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("Invalid hexadecimal string format", nameof(hexString), ex);
        }
    }

    /// <summary>
    /// Parses a SLIP-0039 share from a JSON string.
    /// </summary>
    /// <param name="jsonString">JSON string representation</param>
    /// <returns>Parsed Slip39Share object</returns>
    /// <exception cref="ArgumentException">Thrown when the JSON format is invalid</exception>
    public static Slip39Share ParseFromJson(string jsonString)
    {
        if (string.IsNullOrWhiteSpace(jsonString))
            throw new ArgumentException("JSON string cannot be null or empty", nameof(jsonString));

        try
        {
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };

            var share = JsonSerializer.Deserialize<Slip39Share>(jsonString, options);
            if (share == null)
                throw new ArgumentException("Failed to deserialize JSON to Slip39Share", nameof(jsonString));

            return share;
        }
        catch (JsonException ex)
        {
            throw new ArgumentException("Invalid JSON format", nameof(jsonString), ex);
        }
    }

    /// <summary>
    /// Serializes a SLIP-0039 share to a JSON string.
    /// </summary>
    /// <param name="share">The share to serialize</param>
    /// <param name="indented">Whether to format the JSON with indentation</param>
    /// <returns>JSON string representation</returns>
    public static string ToJson(Slip39Share share, bool indented = true)
    {
        if (share == null)
            throw new ArgumentNullException(nameof(share));

        var options = new JsonSerializerOptions
        {
            WriteIndented = indented,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        return JsonSerializer.Serialize(share, options);
    }

    /// <summary>
    /// Converts an array of mnemonic words to their corresponding indices.
    /// Uses the official SLIP-0039 wordlist for lookup.
    /// </summary>
    private static int[] ConvertWordsToIndices(string[] words)
    {
        var indices = new int[words.Length];
        for (int i = 0; i < words.Length; i++)
        {
            try
            {
                indices[i] = Wordlist.GetIndex(words[i]);
            }
            catch (ArgumentException ex)
            {
                throw new ArgumentException($"Invalid mnemonic word '{words[i]}' at position {i + 1}", ex);
            }
        }
        return indices;
    }

    /// <summary>
    /// Converts word indices to a bit array using big-endian bit ordering.
    /// Each index represents a 10-bit value.
    /// </summary>
    private static bool[] IndicesToBits(int[] indices)
    {
        var bits = new bool[indices.Length * 10];
        for (int i = 0; i < indices.Length; i++)
        {
            var value = indices[i];
            // Use big-endian bit ordering (MSB first)
            for (int j = 0; j < 10; j++)
            {
                bits[i * 10 + j] = (value & (1 << (9 - j))) != 0;
            }
        }
        return bits;
    }

    /// <summary>
    /// Converts a byte array to a bit array using big-endian bit ordering.
    /// </summary>
    private static bool[] BytesToBits(byte[] bytes)
    {
        var bits = new bool[bytes.Length * 8];
        for (int i = 0; i < bytes.Length; i++)
        {
            var value = bytes[i];
            // Use big-endian bit ordering (MSB first)
            for (int j = 0; j < 8; j++)
            {
                bits[i * 8 + j] = (value & (1 << (7 - j))) != 0;
            }
        }
        return bits;
    }

    /// <summary>
    /// Parses a share from a bit array according to the SLIP-0039 specification.
    /// </summary>
    private static Slip39Share ParseFromBits(bool[] bits)
    {
        // Minimum valid share: header(40) + share_value(128) + checksum(30) = 198 bits,
        // rounded up to 20 words × 10 bits = 200 bits.
        if (bits.Length < 200)
            throw new ArgumentException("Bit array too short for valid SLIP-0039 share", nameof(bits));

        int bitIndex = 0;

        // Parse identifier (15 bits)
        var identifier = (ushort)ReadBits(bits, ref bitIndex, 15);

        // Parse extendable flag (1 bit)
        var isExtendable = ReadBits(bits, ref bitIndex, 1) == 1;

        // Parse iteration exponent (4 bits)
        var iterationExponent = (byte)ReadBits(bits, ref bitIndex, 4);

        // Parse group index (4 bits)
        var groupIndex = (byte)ReadBits(bits, ref bitIndex, 4);

        // Parse group threshold (4 bits)
        var groupThreshold = (byte)ReadBits(bits, ref bitIndex, 4);

        // Parse group count (4 bits)
        var groupCount = (byte)ReadBits(bits, ref bitIndex, 4);

        // Parse member index (4 bits)
        var memberIndex = (byte)ReadBits(bits, ref bitIndex, 4);

        // Parse member threshold (4 bits)
        var memberThreshold = (byte)ReadBits(bits, ref bitIndex, 4);

        // Determine share value length directly from the total bit count.
        //
        // Layout: header(40) | padding(p) | shareValue(s) | checksum(30)
        // Invariants:
        //   • totalBits   = bits.Length, an exact multiple of 10 (one word = 10 bits).
        //     Callers are responsible for this: ParseFromMnemonicWords gets it from
        //     IndicesToBits, ParseFromHex trims the byte-alignment slack first.
        //   • p + s       = totalBits - 70   ("remaining" after header and checksum)
        //   • s           is a multiple of 16 bits (SLIP-0039: secret length is a multiple of 2 bytes)
        //   • p ≤ 8       (SLIP-0039: the padding "MUST NOT exceed 8 bits")
        //
        // Because s is a multiple of 16 and p ≤ 8 < 16:
        //   s = (remaining / 16) * 16   (largest multiple of 16 that fits)
        //   p = remaining - s           (equivalently, remaining mod 16)
        int totalBits = bits.Length;
        int remaining = totalBits - 70; // = paddingBits + shareValueBits
        int shareValueBits = (remaining / 16) * 16;
        int paddingBits = remaining - shareValueBits;

        if (paddingBits > 8)
            throw new ArgumentException(
                $"Invalid mnemonic format: computed padding ({paddingBits} bits) exceeds the 8-bit maximum allowed by SLIP-0039",
                nameof(bits));
        
        // The left-padding bits must all be zero: SLIP-0039 states "All padding bits MUST
        // be «0»". Checking here keeps the rule local and gives a diagnostic that names the
        // real problem. Without it the mnemonic is still rejected, but only as a side effect
        // of ValidateShareChecksum re-encoding the share with canonical zero padding, which
        // reports a checksum error and points a reader at the wrong thing — and would vanish
        // silently if that method were ever changed to verify the input words directly.
        for (int i = 0; i < paddingBits; i++)
        {
            if (bits[bitIndex + i])
                throw new ArgumentException(
                    "Invalid mnemonic padding: the bits padding the share value must all be zero",
                    nameof(bits));
        }

        bitIndex += paddingBits;
        
        // Calculate share value bytes
        int shareValueBytes = shareValueBits / 8;

        // Parse share value (after skipping padding)
        var shareValue = new byte[shareValueBytes];
        for (int i = 0; i < shareValueBytes; i++)
        {
            shareValue[i] = (byte)ReadBits(bits, ref bitIndex, 8);
        }

        // Parse checksum (30 bits)
        var checksum = (uint)ReadBits(bits, ref bitIndex, 30);

        var share = new Slip39Share(identifier, isExtendable, iterationExponent,
            groupIndex, groupThreshold, groupCount, memberIndex, memberThreshold,
            shareValue, checksum);

        // Validate checksum
        if (!ValidateShareChecksum(share))
        {
            throw new ArgumentException("Invalid mnemonic checksum");
        }

        return share;
    }

    /// <summary>
    /// Reads a specified number of bits from a bit array starting at the given index.
    /// </summary>
    private static uint ReadBits(bool[] bits, ref int startIndex, int bitCount)
    {
        if (startIndex + bitCount > bits.Length)
            throw new ArgumentException("Not enough bits remaining to read the requested number");

        uint value = 0;
        for (int i = 0; i < bitCount; i++)
        {
            if (bits[startIndex + i])
            {
                value |= (uint)(1 << (bitCount - 1 - i));
            }
        }
        startIndex += bitCount;
        return value;
    }

    /// <summary>
    /// Validates the checksum of a SLIP-0039 share.
    /// </summary>
    /// <param name="share">The share to validate</param>
    /// <returns>True if the checksum is valid, false otherwise</returns>
    private static bool ValidateShareChecksum(Slip39Share share)
    {
        try
        {
            // Convert share back to mnemonic indices for checksum validation
            var indices = ShareToIndices(share);
            
            // Verify checksum using RS1024
            // Convert int array to ushort array
            var ushortIndices = new ushort[indices.Length];
            for (int i = 0; i < indices.Length; i++)
            {
                ushortIndices[i] = (ushort)indices[i];
            }
            return Rs1024Checksum.VerifyChecksum(ushortIndices, share.IsExtendable);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Converts a share back to its mnemonic word indices.
    /// </summary>
    public static int[] ShareToIndices(Slip39Share share)
    {
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
        
        // Pack header data into bits
        WriteBits(bits, ref bitIndex, share.Identifier, 15);
        WriteBits(bits, ref bitIndex, share.IsExtendable ? 1u : 0u, 1);
        WriteBits(bits, ref bitIndex, share.IterationExponent, 4);
        WriteBits(bits, ref bitIndex, share.GroupIndex, 4);
        WriteBits(bits, ref bitIndex, share.GroupThreshold, 4);
        WriteBits(bits, ref bitIndex, share.GroupCount, 4);
        WriteBits(bits, ref bitIndex, share.MemberIndex, 4);
        WriteBits(bits, ref bitIndex, share.MemberThreshold, 4);
        
        // Add left-padding bits (should be 0s according to SLIP-39 spec)
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
        
        // Convert bits back to indices
        var indices = new int[wordCount];
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
            indices[i] = (int)value;
        }
        
        return indices;
    }
    
    /// <summary>
    /// Writes bits to a bit array at the specified position.
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
    /// Validates that a share has the correct format and structure.
    /// </summary>
    /// <param name="share">The share to validate</param>
    /// <returns>True if the share is valid, false otherwise</returns>
    public static bool ValidateShare(Slip39Share share)
    {
        if (share == null) return false;

        try
        {
            // Check field ranges
            if (share.Identifier > 0x7FFF) return false;
            if (share.IterationExponent > 15) return false;
            if (share.GroupIndex > 15) return false;
            if (share.GroupThreshold > 15) return false;
            if (share.GroupCount > 15) return false;
            if (share.MemberIndex > 15) return false;
            if (share.MemberThreshold > 15) return false;
            if (share.Checksum > 0x3FFFFFFF) return false;

            // Check logical consistency
            if (!share.IsLogicallyValid()) return false;

            return true;
        }
        catch
        {
            return false;
        }
    }
}
