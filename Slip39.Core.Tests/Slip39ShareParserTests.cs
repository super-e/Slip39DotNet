using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Slip39.Core;
using Xunit;

namespace Slip39.Core.Tests;

/// <summary>
/// Unit tests for the Slip39ShareParser class.
/// Tests parsing functionality for mnemonic words, hexadecimal strings, and JSON.
/// </summary>
public class Slip39ShareParserTests
{
    private readonly Slip39Share _testShare;
    private readonly string _testHex;
    private readonly string _testJson;

    public Slip39ShareParserTests()
    {
        // Create a test share with known values. The checksum is the real RS1024 checksum of
        // the other fields: it used to be an arbitrary number, which made the fixture a share
        // no parser would now accept — ParseFromJson included.
        _testShare = WithValidChecksum(new Slip39Share(
            identifier: 12345,
            isExtendable: false,
            iterationExponent: 1,
            groupIndex: 0,
            groupThreshold: 1,
            groupCount: 1,
            memberIndex: 0,
            memberThreshold: 2,
            shareValue: new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
            checksum: 0
        ));

        // Generate test hex from the share
        _testHex = _testShare.ToHex();

        // Generate test JSON from the share
        _testJson = Slip39ShareParser.ToJson(_testShare);
    }

    /// <summary>
    /// Returns the same share carrying the RS1024 checksum its fields actually imply.
    /// </summary>
    private static Slip39Share WithValidChecksum(Slip39Share draft)
    {
        var indices = Slip39ShareParser.ShareToIndices(draft);
        var data = indices.Take(indices.Length - 3).Select(i => (ushort)i).ToArray();
        var words = Rs1024Checksum.GenerateChecksum(data, draft.IsExtendable);
        uint checksum = ((uint)words[0] << 20) | ((uint)words[1] << 10) | words[2];

        return new Slip39Share(
            draft.Identifier, draft.IsExtendable, draft.IterationExponent,
            draft.GroupIndex, draft.GroupThreshold, draft.GroupCount,
            draft.MemberIndex, draft.MemberThreshold, draft.ShareValue, checksum);
    }

    #region Mnemonic Padding Tests

    /// <summary>
    /// Official SLIP-0039 vectors 3 and 22, "Mnemonic with invalid padding". Both were already
    /// rejected before the padding check existed, but only indirectly: ValidateShareChecksum
    /// re-encodes the share with canonical zero padding, so corrupt padding surfaced as a
    /// checksum failure. Asserting on the message is the point — it is what distinguishes the
    /// explicit local check from that emergent behaviour, and it fails if the check is removed.
    /// </summary>
    public static TheoryData<string> InvalidPaddingMnemonics => new()
    {
        // 3. Mnemonic with invalid padding (128 bits)
        "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness",
        // 22. Mnemonic with invalid padding (256 bits)
        "theory painting academic academic campus sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips facility obtain sister",
    };

    [Theory]
    [MemberData(nameof(InvalidPaddingMnemonics))]
    public void ParseFromMnemonic_NonZeroPadding_ReportsPaddingNotChecksum(string mnemonic)
    {
        // Act
        var ex = Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromMnemonic(mnemonic));

        // Assert
        Assert.Contains("padding", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("checksum", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ParseFromMnemonic_BadWord_StillReportsChecksum_NotPadding()
    {
        // Arrange — vector 2, "Mnemonic with invalid checksum (128 bits)": the padding is fine,
        // so the padding check must not swallow genuine checksum failures.
        const string mnemonic = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney";

        // Act
        var ex = Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromMnemonic(mnemonic));

        // Assert
        Assert.Contains("checksum", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    #endregion

    #region Hex Parsing Tests

    /// <summary>
    /// Official SLIP-0039 test vectors, used here because a hex round-trip needs shares whose
    /// checksum actually validates. Both mnemonic lengths matter: 20 words is 200 bits, the one
    /// case that happens to land on a byte boundary, while 33 words is 330 bits and forces the
    /// parser to discard the trailing byte-alignment slack.
    /// </summary>
    public static TheoryData<string, int> ValidMnemonics => new()
    {
        // 1. Valid mnemonic without sharing (128 bits) — 20 words, 200 bits, byte aligned
        { "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard", 16 },
        // 20. Valid mnemonic without sharing (256 bits) — 33 words, 330 bits, 6 slack bits in hex
        { "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect luck", 32 },
    };

    [Theory]
    [MemberData(nameof(ValidMnemonics))]
    public void ToHex_ThenParseFromHex_RoundTripsAllFields(string mnemonic, int expectedShareValueLength)
    {
        // Arrange
        var original = Slip39ShareParser.ParseFromMnemonic(mnemonic);
        Assert.Equal(expectedShareValueLength, original.ShareValue.Length);

        // Act
        var reparsed = Slip39ShareParser.ParseFromHex(original.ToHex());

        // Assert
        Assert.Equal(original.Identifier, reparsed.Identifier);
        Assert.Equal(original.IsExtendable, reparsed.IsExtendable);
        Assert.Equal(original.IterationExponent, reparsed.IterationExponent);
        Assert.Equal(original.GroupIndex, reparsed.GroupIndex);
        Assert.Equal(original.GroupThreshold, reparsed.GroupThreshold);
        Assert.Equal(original.GroupCount, reparsed.GroupCount);
        Assert.Equal(original.MemberIndex, reparsed.MemberIndex);
        Assert.Equal(original.MemberThreshold, reparsed.MemberThreshold);
        Assert.Equal(original.Checksum, reparsed.Checksum);
        Assert.Equal(original.ShareValue, reparsed.ShareValue);
    }

    [Theory]
    [MemberData(nameof(ValidMnemonics))]
    public void ToHex_AndToMnemonic_EncodeTheSameBits(string mnemonic, int expectedShareValueLength)
    {
        // Arrange
        var share = Slip39ShareParser.ParseFromMnemonic(mnemonic);
        Assert.Equal(expectedShareValueLength, share.ShareValue.Length);

        // Act
        var hexBits = Convert.FromHexString(share.ToHex())
            .SelectMany(b => Enumerable.Range(0, 8).Select(i => (b & (1 << (7 - i))) != 0));
        var mnemonicBits = Slip39ShareParser.ShareToIndices(share)
            .SelectMany(w => Enumerable.Range(0, 10).Select(i => (w & (1 << (9 - i))) != 0));

        // Assert — the hex form is the mnemonic bit stream plus zero padding to a byte boundary
        var expected = mnemonicBits.ToList();
        var actual = hexBits.ToList();
        Assert.Equal(expected, actual.Take(expected.Count));
        Assert.All(actual.Skip(expected.Count), bit => Assert.False(bit));
        Assert.True(actual.Count - expected.Count < 8);
    }

    [Theory]
    [MemberData(nameof(ValidMnemonics))]
    public void ToMnemonic_ThenParseFromMnemonic_RoundTripsExactly(string mnemonic, int expectedShareValueLength)
    {
        // Arrange
        var original = Slip39ShareParser.ParseFromMnemonic(mnemonic);
        Assert.Equal(expectedShareValueLength, original.ShareValue.Length);

        // Act & Assert
        Assert.Equal(mnemonic, original.ToMnemonic());
        Assert.Equal(original.ShareValue, Slip39ShareParser.ParseFromMnemonic(original.ToMnemonic()).ShareValue);
    }

    [Fact]
    public void ParseFromHex_EmptyString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromHex(""));
    }

    [Fact]
    public void ParseFromHex_NullString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromHex(null));
    }

    [Fact]
    public void ParseFromHex_OddLengthHex_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromHex("12345"));
    }

    [Fact]
    public void ParseFromHex_InvalidHexCharacters_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromHex("123G"));
    }

    #endregion

    #region JSON Parsing Tests

    [Fact]
    public void ParseFromJson_ValidJson_ReturnsCorrectShare()
    {
        // Act
        var parsedShare = Slip39ShareParser.ParseFromJson(_testJson);

        // Assert
        Assert.Equal(_testShare.Identifier, parsedShare.Identifier);
        Assert.Equal(_testShare.IsExtendable, parsedShare.IsExtendable);
        Assert.Equal(_testShare.IterationExponent, parsedShare.IterationExponent);
        Assert.Equal(_testShare.GroupIndex, parsedShare.GroupIndex);
        Assert.Equal(_testShare.GroupThreshold, parsedShare.GroupThreshold);
        Assert.Equal(_testShare.GroupCount, parsedShare.GroupCount);
        Assert.Equal(_testShare.MemberIndex, parsedShare.MemberIndex);
        Assert.Equal(_testShare.MemberThreshold, parsedShare.MemberThreshold);
        Assert.Equal(_testShare.ShareValue, parsedShare.ShareValue);
        Assert.Equal(_testShare.Checksum, parsedShare.Checksum);
    }

    [Fact]
    public void ToJson_ValidShare_ReturnsValidJson()
    {
        // Act
        var json = Slip39ShareParser.ToJson(_testShare);

        // Assert
        Assert.NotNull(json);
        Assert.Contains("identifier", json);
        Assert.Contains("extendable", json);
        Assert.Contains("shareValue", json);

        // Verify it can be parsed back
        var reparsed = Slip39ShareParser.ParseFromJson(json);
        Assert.Equal(_testShare.Identifier, reparsed.Identifier);
    }

    [Fact]
    public void ToJson_WithIndentation_ReturnsFormattedJson()
    {
        // Act
        var json = Slip39ShareParser.ToJson(_testShare, indented: true);

        // Assert
        Assert.True(json.Contains("\n") || json.Contains("\r"));
    }

    [Fact]
    public void ToJson_WithoutIndentation_ReturnsCompactJson()
    {
        // Act
        var json = Slip39ShareParser.ToJson(_testShare, indented: false);

        // Assert
        Assert.DoesNotContain("\n", json);
        Assert.DoesNotContain("\r", json);
    }

    [Fact]
    public void ParseFromJson_EmptyString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromJson(""));
    }

    [Fact]
    public void ParseFromJson_NullString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromJson(null));
    }

    [Fact]
    public void ParseFromJson_InvalidJson_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromJson("{ invalid json }"));
    }

    [Fact]
    public void ToJson_NullShare_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Slip39ShareParser.ToJson(null));
    }

    #endregion

    #region Mnemonic Parsing Tests

    [Fact]
    public void ParseFromMnemonic_ValidMnemonic20Words_ParsesSuccessfully()
    {
        // Arrange - Use a valid 20-word SLIP-39 test vector mnemonic
        var mnemonic = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard";

        // Act & Assert - Should not throw
        var result = Slip39ShareParser.ParseFromMnemonic(mnemonic);
        Assert.NotNull(result);
    }


    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    [InlineData("\t")]
    [InlineData("  ")]
    [InlineData(" \n\t ")]
    public void ParseFromMnemonic_SeparatedByAnyWhitespace_ParsesTheSameShare(string separator)
    {
        // A share pasted out of a file, a printed backup or a multi-line message arrives with
        // line breaks in it. Splitting on ' ' alone rejected those as "Expected at least 20
        // words, got 1" — an error about the share, for what was only a line break.
        const string canonical = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard";
        var reflowed = string.Join(separator, canonical.Split(' '));

        var expected = Slip39ShareParser.ParseFromMnemonic(canonical);
        var actual = Slip39ShareParser.ParseFromMnemonic(reflowed);

        Assert.Equal(expected.ToMnemonic(), actual.ToMnemonic());
        Assert.Equal(expected.ShareValue, actual.ShareValue);
    }

    [Fact]
    public void ParseFromMnemonic_SurroundingWhitespace_IsIgnored()
    {
        const string canonical = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard";

        var actual = Slip39ShareParser.ParseFromMnemonic($"\n\t {canonical} \r\n");

        Assert.Equal(canonical, actual.ToMnemonic());
    }

    [Fact]
    public void ParseFromMnemonicWords_ValidWordArray_ParsesSuccessfully()
    {
        // Arrange - Use real SLIP-39 words
        var words = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard".Split(' ');

        // Act
        var result = Slip39ShareParser.ParseFromMnemonicWords(words);

        // Assert
        Assert.NotNull(result);
    }

    [Fact]
    public void ParseFromMnemonic_InvalidWordCount_ThrowsArgumentException()
    {
        // Arrange - Invalid word count
        var mnemonic = "word1 word2 word3";

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromMnemonic(mnemonic));
    }

    [Fact]
    public void ParseFromMnemonic_EmptyString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromMnemonic(""));
    }

    [Fact]
    public void ParseFromMnemonic_NullString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromMnemonic(null));
    }

    [Fact]
    public void ParseFromMnemonicWords_NullArray_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Slip39ShareParser.ParseFromMnemonicWords(null));
    }

    #endregion

    #region Validation Tests

    [Fact]
    public void ValidateShare_ValidShare_ReturnsTrue()
    {
        // Act
        var isValid = Slip39ShareParser.ValidateShare(_testShare);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void ValidateShare_NullShare_ReturnsFalse()
    {
        // Act
        var isValid = Slip39ShareParser.ValidateShare(null);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void ValidateShare_InvalidIdentifier_ThrowsException()
    {
        // Act & Assert - Constructor should throw for invalid identifier
        Assert.Throws<ArgumentOutOfRangeException>(() => new Slip39Share(
            identifier: 0x8000, // 16 bits, should be max 15
            isExtendable: false,
            iterationExponent: 1,
            groupIndex: 0,
            groupThreshold: 1,
            groupCount: 1,
            memberIndex: 0,
            memberThreshold: 2,
            shareValue: new byte[] { 0x01, 0x02 },
            checksum: 123
        ));
    }

    [Fact]
    public void ValidateShare_InvalidIterationExponent_ThrowsException()
    {
        // Act & Assert - Constructor should throw for invalid iteration exponent
        Assert.Throws<ArgumentOutOfRangeException>(() => new Slip39Share(
            identifier: 123,
            isExtendable: false,
            iterationExponent: 16, // > 4 bits
            groupIndex: 0,
            groupThreshold: 1,
            groupCount: 1,
            memberIndex: 0,
            memberThreshold: 2,
            shareValue: new byte[] { 0x01, 0x02 },
            checksum: 123
        ));
    }

    [Fact]
    public void ValidateShare_InvalidChecksum_ThrowsException()
    {
        // Act & Assert - Constructor should throw for invalid checksum
        Assert.Throws<ArgumentOutOfRangeException>(() => new Slip39Share(
            identifier: 123,
            isExtendable: false,
            iterationExponent: 1,
            groupIndex: 0,
            groupThreshold: 1,
            groupCount: 1,
            memberIndex: 0,
            memberThreshold: 2,
            shareValue: new byte[] { 0x01, 0x02 },
            checksum: 0x40000000 // > 30 bits
        ));
    }

    #endregion

    #region JSON is checked the same way the other two parsers are

    /// <summary>
    /// The JSON of the fixture share, with one field replaced.
    /// </summary>
    private string TamperedJson(string field, string value)
    {
        var doc = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(_testJson)!;
        doc[field] = JsonSerializer.Deserialize<JsonElement>(value);
        return JsonSerializer.Serialize(doc);
    }

    [Fact]
    public void ParseFromJson_AlteredChecksum_IsRejected()
    {
        // The reproduction from the issue: the checksum was accepted verbatim, whatever it was.
        var json = TamperedJson("checksum", "12345");

        var ex = Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromJson(json));
        Assert.Contains("checksum", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ParseFromJson_AlteredField_IsRejectedByTheChecksum()
    {
        // Every field is covered by the checksum, so changing one and leaving the checksum
        // alone is caught even though the new value is in range.
        var json = TamperedJson("memberIndex", "3");

        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromJson(json));
    }

    [Theory]
    [InlineData("identifier", "65535")]        // 16 bits, must be 15
    [InlineData("iterationExponent", "200")]   // must be 4 bits
    [InlineData("groupIndex", "16")]
    [InlineData("memberThreshold", "16")]
    [InlineData("checksum", "4294967295")]     // must be 30 bits
    public void ParseFromJson_FieldOutOfRange_IsRejected(string field, string value)
    {
        // These used to be accepted: System.Text.Json built the object through the
        // parameterless constructor and the setters, so the constructor's range checks never
        // ran. ShareToIndices then masked the field down to its bit width, and an identifier of
        // 65535 produced a mnemonic starting with "zero" instead of an error.
        var json = TamperedJson(field, value);

        Assert.Throws<ArgumentOutOfRangeException>(() => Slip39ShareParser.ParseFromJson(json));
    }

    [Fact]
    public void ParseFromJson_MissingShareValue_IsRejected()
    {
        var doc = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(_testJson)!;
        doc.Remove("shareValue");

        var ex = Assert.Throws<ArgumentException>(
            () => Slip39ShareParser.ParseFromJson(JsonSerializer.Serialize(doc)));
        Assert.Contains("share value is missing", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ParseFromJson_AgreesWithTheOtherTwoParsers()
    {
        // The same share, read three ways, must produce the same object — and be accepted or
        // rejected on the same terms. That equivalence is what the JSON path was missing.
        const string mnemonic = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard";
        var fromMnemonic = Slip39ShareParser.ParseFromMnemonic(mnemonic);

        var fromHex = Slip39ShareParser.ParseFromHex(fromMnemonic.ToHex());
        var fromJson = Slip39ShareParser.ParseFromJson(Slip39ShareParser.ToJson(fromMnemonic));

        Assert.Equal(mnemonic, fromHex.ToMnemonic());
        Assert.Equal(mnemonic, fromJson.ToMnemonic());
        Assert.Equal(fromMnemonic.Checksum, fromJson.Checksum);
        Assert.Equal(fromMnemonic.ShareValue, fromJson.ShareValue);
    }

    #endregion

    #region Round-trip Tests


    [Fact]
    public void RoundTrip_JsonToShareToJson_PreservesData()
    {
        // Act
        var parsedShare = Slip39ShareParser.ParseFromJson(_testJson);
        var regeneratedJson = Slip39ShareParser.ToJson(parsedShare);

        // Parse both JSON strings to compare values (since formatting might differ)
        var originalData = JsonSerializer.Deserialize<JsonElement>(_testJson);
        var regeneratedData = JsonSerializer.Deserialize<JsonElement>(regeneratedJson);

        // Assert key fields are equal
        Assert.Equal(originalData.GetProperty("identifier").GetUInt16(), 
                       regeneratedData.GetProperty("identifier").GetUInt16());
        Assert.Equal(originalData.GetProperty("extendable").GetBoolean(), 
                       regeneratedData.GetProperty("extendable").GetBoolean());
    }

    #endregion

    #region Edge Cases


    [Fact]
    public void ParseFromMnemonic_ExtraWhitespace_HandlesGracefully()
    {
        // Arrange - Use real SLIP-39 words with extra whitespace
        var words = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard".Split(' ');
        var mnemonicWithExtraSpaces = "  " + string.Join("   ", words) + "  ";

        // Act
        var result = Slip39ShareParser.ParseFromMnemonic(mnemonicWithExtraSpaces);

        // Assert
        Assert.NotNull(result);
    }

    #endregion
}
