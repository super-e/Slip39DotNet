using Newtonsoft.Json;

namespace Slip39.Core.Tests;

/// <summary>
/// Tests to validate the structure and content of the reference test vectors
/// without requiring the actual SLIP-0039 implementation to be complete.
/// </summary>
public class TestVectorValidationTests
{
    private static readonly Lazy<object[][]> _rawTestVectors = new(() => LoadRawTestVectors());

    private static object[][] RawTestVectors => _rawTestVectors.Value;

    private static object[][] LoadRawTestVectors()
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
        var vectors = JsonConvert.DeserializeObject<object[][]>(json);
        
        return vectors ?? throw new InvalidOperationException("Failed to parse test vectors JSON");
    }

    [Fact]
    public void TestVectors_ShouldLoadFromFile()
    {
        // Verify that the vectors.json file exists and can be loaded
        var vectors = RawTestVectors;
        Assert.NotNull(vectors);
        Assert.NotEmpty(vectors);
    }

    [Fact]
    public void TestVectors_ShouldHaveExpectedCount()
    {
        // Verify we have approximately the expected number of test cases
        var vectors = RawTestVectors;
        Assert.True(vectors.Length >= 40, $"Expected at least 40 test vectors, got {vectors.Length}");
        Assert.True(vectors.Length <= 50, $"Expected at most 50 test vectors, got {vectors.Length}");
    }

    [Fact]
    public void TestVectors_ShouldHaveValidStructure()
    {
        var vectors = RawTestVectors;
        
        foreach (var vector in vectors)
        {
            // Each vector should have exactly 4 elements
            Assert.True(vector.Length == 4, 
                $"Test vector should have 4 elements, but has {vector.Length}");
            
            // First element should be a description string
            Assert.True(vector[0] is string, "First element should be a description string");
            
            // Second element should be an array of mnemonics
            Assert.True(vector[1] is Newtonsoft.Json.Linq.JArray, 
                "Second element should be an array of mnemonic strings");
            
            // Third and fourth elements should be strings (could be empty for invalid cases)
            Assert.True(vector[2] is string, "Third element should be a string (master secret)");
            Assert.True(vector[3] is string, "Fourth element should be a string (master key)");
        }
    }

    [Fact]
    public void TestVectors_ShouldContainValidCases()
    {
        var vectors = RawTestVectors;
        var validCases = vectors.Where(v => !string.IsNullOrEmpty(v[2]?.ToString())).ToArray();
        
        // Should have multiple valid test cases
        Assert.True(validCases.Length >= 10, 
            $"Expected at least 10 valid test cases, got {validCases.Length}");
    }

    [Fact]
    public void TestVectors_ShouldContainInvalidCases()
    {
        var vectors = RawTestVectors;
        var invalidCases = vectors.Where(v => string.IsNullOrEmpty(v[2]?.ToString())).ToArray();
        
        // Should have multiple invalid test cases to verify error handling
        Assert.True(invalidCases.Length >= 15, 
            $"Expected at least 15 invalid test cases, got {invalidCases.Length}");
    }

    [Fact]
    public void TestVectors_ShouldContain128BitCases()
    {
        var vectors = RawTestVectors;
        var bit128Cases = vectors.Where(v => 
            v[0]?.ToString()?.Contains("128 bits", StringComparison.OrdinalIgnoreCase) == true).ToArray();
        
        Assert.True(bit128Cases.Length >= 10, 
            $"Expected at least 10 128-bit test cases, got {bit128Cases.Length}");
    }

    [Fact]
    public void TestVectors_ShouldContain256BitCases()
    {
        var vectors = RawTestVectors;
        var bit256Cases = vectors.Where(v => 
            v[0]?.ToString()?.Contains("256 bits", StringComparison.OrdinalIgnoreCase) == true).ToArray();
        
        Assert.True(bit256Cases.Length >= 10, 
            $"Expected at least 10 256-bit test cases, got {bit256Cases.Length}");
    }

    [Fact]
    public void TestVectors_ValidCases_ShouldHaveNonEmptyMasterSecrets()
    {
        var vectors = RawTestVectors;
        
        foreach (var vector in vectors)
        {
            var description = vector[0]?.ToString() ?? "";
            var masterSecret = vector[2]?.ToString() ?? "";
            
            if (!string.IsNullOrEmpty(masterSecret))
            {
                // Valid cases should have hex-encoded master secrets
                Assert.True(masterSecret.Length >= 32, 
                    $"Master secret should be at least 32 hex characters for test: {description}");
                Assert.True(IsValidHex(masterSecret), 
                    $"Master secret should be valid hex for test: {description}");
            }
        }
    }

    [Fact]
    public void TestVectors_ValidCases_ShouldHaveMasterKeys()
    {
        var vectors = RawTestVectors;
        
        foreach (var vector in vectors)
        {
            var description = vector[0]?.ToString() ?? "";
            var masterSecret = vector[2]?.ToString() ?? "";
            var masterKey = vector[3]?.ToString() ?? "";
            
            if (!string.IsNullOrEmpty(masterSecret))
            {
                // Valid cases should have master keys (typically starting with 'xprv')
                Assert.False(string.IsNullOrEmpty(masterKey), 
                    $"Valid test case should have master key for test: {description}");
                Assert.True(masterKey.StartsWith("xprv"), 
                    $"Master key should start with 'xprv' for test: {description}");
            }
        }
    }

    [Theory]
    [InlineData("1. Valid mnemonic without sharing (128 bits)")]
    [InlineData("4. Basic sharing 2-of-3 (128 bits)")]
    [InlineData("20. Valid mnemonic without sharing (256 bits)")]
    [InlineData("23. Basic sharing 2-of-3 (256 bits)")]
    public void TestVectors_ShouldContainExpectedTestCases(string expectedDescription)
    {
        var vectors = RawTestVectors;
        var foundCase = vectors.FirstOrDefault(v => 
            v[0]?.ToString()?.Equals(expectedDescription, StringComparison.OrdinalIgnoreCase) == true);
        
        Assert.NotNull(foundCase);
    }

    private static bool IsValidHex(string hex)
    {
        return hex.All(c => char.IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
    }
}
