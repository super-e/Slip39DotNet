using Newtonsoft.Json;
using Slip39.Core;

namespace Slip39.Core.Tests;

/// <summary>
/// Test class that runs against the official SLIP-0039 reference test vectors
/// from the Trezor implementation to ensure compatibility.
/// </summary>
public class Slip39ReferenceVectorTests
{
    private static readonly Lazy<TestVector[]> _testVectors = new(() => LoadTestVectors());

    private static TestVector[] TestVectors => _testVectors.Value;

    private static TestVector[] LoadTestVectors()
    {
        // AppContext.BaseDirectory, not Directory.GetCurrentDirectory(): the csproj copies
        // vectors.json next to the test assembly, and the working directory is the runner's to
        // choose. They happen to coincide under `dotnet test` today.
        var vectorsPath = Path.Join(AppContext.BaseDirectory, "vectors.json");

        if (!File.Exists(vectorsPath))
        {
            throw new FileNotFoundException($"Test vectors file not found at: {vectorsPath}");
        }

        var json = File.ReadAllText(vectorsPath);
        var rawVectors = JsonConvert.DeserializeObject<object[][]>(json);
        
        if (rawVectors == null)
        {
            throw new InvalidOperationException("Failed to parse test vectors JSON");
        }

        var vectors = new List<TestVector>();
        
        foreach (var rawVector in rawVectors)
        {
            if (rawVector.Length >= 4)
            {
                var description = rawVector[0]?.ToString() ?? "";
                var mnemonics = rawVector[1] as Newtonsoft.Json.Linq.JArray;
                var expectedSecret = rawVector[2]?.ToString() ?? "";
                var expectedMasterKey = rawVector[3]?.ToString() ?? "";

                var mnemonicStrings = mnemonics?.Select(m => m.ToString()).ToArray() ?? Array.Empty<string>();

                vectors.Add(new TestVector
                {
                    Description = description,
                    Mnemonics = mnemonicStrings,
                    ExpectedMasterSecret = expectedSecret,
                    ExpectedMasterKey = expectedMasterKey,
                    IsValid = !string.IsNullOrEmpty(expectedSecret)
                });
            }
        }

        return vectors.ToArray();
    }

    [Fact]
    public void TestVectors_ShouldLoadSuccessfully()
    {
        // Verify that test vectors load without errors
        var vectors = TestVectors;
        Assert.NotEmpty(vectors);
        Assert.True(vectors.Length > 40, "Should have loaded all test vectors");
    }

    [Theory]
    [MemberData(nameof(GetValidTestVectors))]
    public void ValidMnemonics_ShouldRecoverCorrectMasterSecret(TestVector testVector)
    {
        // Arrange & Act
        var result = Slip39.CombineMnemonics(testVector.Mnemonics, "TREZOR");

        // Assert
        Assert.True(result.IsSuccess, $"Failed to combine mnemonics for test: {testVector.Description}");
        
        var masterSecretHex = Convert.ToHexString(result.MasterSecret).ToLowerInvariant();
        Assert.Equal(testVector.ExpectedMasterSecret.ToLowerInvariant(), masterSecretHex);
    }

    [Theory]
    [MemberData(nameof(GetValidTestVectors))]
    public void ValidMnemonics_ShouldGenerateCorrectMasterKey(TestVector testVector)
    {
        // Skip if no expected master key is provided
        if (string.IsNullOrEmpty(testVector.ExpectedMasterKey))
            return;

        // Arrange & Act - Use TREZOR passphrase for consistency
        var result = Slip39.CombineMnemonics(testVector.Mnemonics, "TREZOR");
        Assert.True(result.IsSuccess, $"Failed to combine mnemonics for test: {testVector.Description}");

        var masterKey = Slip39.GenerateMasterKey(result.MasterSecret);

        // Assert
        Assert.Equal(testVector.ExpectedMasterKey, masterKey);
    }

    [Theory]
    [MemberData(nameof(GetInvalidTestVectors))]
    public void InvalidMnemonics_ShouldFail(TestVector testVector)
    {
        // Arrange & Act
        var result = Slip39.CombineMnemonics(testVector.Mnemonics);

        // Assert
        Assert.False(result.IsSuccess, $"Expected failure for test: {testVector.Description}");
    }

    [Theory]
    [MemberData(nameof(GetSingleValidMnemonicVectors))]
    public void SingleValidMnemonic_ShouldRecoverCorrectly(TestVector testVector)
    {
        // Test single mnemonic without sharing
        Assert.Single(testVector.Mnemonics);

        // Arrange & Act
        var result = Slip39.CombineMnemonics(testVector.Mnemonics, "TREZOR");

        // Assert
        Assert.True(result.IsSuccess, $"Failed to recover single mnemonic for test: {testVector.Description}");
        
        var masterSecretHex = Convert.ToHexString(result.MasterSecret).ToLowerInvariant();
        Assert.Equal(testVector.ExpectedMasterSecret.ToLowerInvariant(), masterSecretHex);
    }

    [Theory]
    [MemberData(nameof(GetMultiShareValidVectors))]
    public void MultiShareValid_ShouldRecoverCorrectly(TestVector testVector)
    {
        // Test multi-share valid scenarios
        Assert.True(testVector.Mnemonics.Length > 1);

        // Arrange & Act - Use TREZOR passphrase for consistency
        var result = Slip39.CombineMnemonics(testVector.Mnemonics, "TREZOR");

        // Assert
        Assert.True(result.IsSuccess, $"Failed to recover multi-share for test: {testVector.Description}");
        
        var masterSecretHex = Convert.ToHexString(result.MasterSecret).ToLowerInvariant();
        Assert.Equal(testVector.ExpectedMasterSecret.ToLowerInvariant(), masterSecretHex);
    }

    public static IEnumerable<object[]> GetValidTestVectors()
    {
        return TestVectors.Where(v => v.IsValid).Select(v => new object[] { v });
    }

    public static IEnumerable<object[]> GetInvalidTestVectors()
    {
        return TestVectors.Where(v => !v.IsValid).Select(v => new object[] { v });
    }

    public static IEnumerable<object[]> GetSingleValidMnemonicVectors()
    {
        return TestVectors.Where(v => v.IsValid && v.Mnemonics.Length == 1).Select(v => new object[] { v });
    }

    public static IEnumerable<object[]> GetMultiShareValidVectors()
    {
        return TestVectors.Where(v => v.IsValid && v.Mnemonics.Length > 1).Select(v => new object[] { v });
    }
}

/// <summary>
/// Represents a test vector from the reference implementation
/// </summary>
public class TestVector
{
    public string Description { get; set; } = "";
    public string[] Mnemonics { get; set; } = Array.Empty<string>();
    public string ExpectedMasterSecret { get; set; } = "";
    public string ExpectedMasterKey { get; set; } = "";
    public bool IsValid { get; set; }

    public override string ToString() => Description;
}
