using System.Security.Cryptography;
using Slip39.Core;
using Xunit;

namespace Slip39.Core.Tests;

/// <summary>
/// Unit tests for polynomial interpolation and Shamir's secret sharing functionality.
/// Tests the implementation against known values and edge cases.
/// </summary>
public class PolynomialInterpolationTests
{
    #region Lagrange Interpolation Tests

    [Fact]
    public void Interpolate_SinglePoint_ReturnsCorrectValue()
    {
        // Arrange
        var points = new List<(byte index, byte[] values)>
        {
            (5, new byte[] { 42, 100 })
        };

        // Act
        var result = PolynomialInterpolation.Interpolate(5, points);

        // Assert
        Assert.Equal(new byte[] { 42, 100 }, result);
    }

    [Fact]
    public void Interpolate_TwoPoints_Linear()
    {
        // Arrange - Simple linear function: f(x) = x + 1 over GF(256)
        var points = new List<(byte index, byte[] values)>
        {
            (0, new byte[] { 1 }),  // f(0) = 1
            (1, new byte[] { 0 })   // f(1) = 0 (since 1+1=2=0 in GF(256))
        };

        // Act & Assert
        var result0 = PolynomialInterpolation.Interpolate(0, points);
        var result1 = PolynomialInterpolation.Interpolate(1, points);
        var result2 = PolynomialInterpolation.Interpolate(2, points);

        Assert.Equal(new byte[] { 1 }, result0);
        Assert.Equal(new byte[] { 0 }, result1);
        Assert.Equal(new byte[] { 3 }, result2); // f(2) = 2+1 = 3
    }

    [Fact]
    public void Interpolate_ThreePoints_Quadratic()
    {
        // Arrange - Known quadratic polynomial points
        var points = new List<(byte index, byte[] values)>
        {
            (1, new byte[] { 5 }),
            (2, new byte[] { 17 }),
            (3, new byte[] { 37 })
        };

        // Act
        var result0 = PolynomialInterpolation.Interpolate(0, points);
        var result4 = PolynomialInterpolation.Interpolate(4, points);

        // Assert
        Assert.NotNull(result0);
        Assert.NotNull(result4);
        Assert.Single(result0);
        Assert.Single(result4);
    }

    [Fact]
    public void Interpolate_MultiByteValues_WorksCorrectly()
    {
        // Arrange
        var points = new List<(byte index, byte[] values)>
        {
            (1, new byte[] { 10, 20, 30 }),
            (2, new byte[] { 15, 25, 35 }),
            (3, new byte[] { 20, 30, 40 })
        };

        // Act
        var result = PolynomialInterpolation.Interpolate(0, points);

        // Assert
        Assert.Equal(3, result.Length);
    }

    [Fact]
    public void Interpolate_EmptyPoints_ThrowsArgumentException()
    {
        // Arrange
        var points = new List<(byte index, byte[] values)>();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            PolynomialInterpolation.Interpolate(5, points));
    }

    [Fact]
    public void Interpolate_NullPoints_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => 
            PolynomialInterpolation.Interpolate(5, null));
    }

    [Fact]
    public void Interpolate_DifferentValueLengths_ThrowsArgumentException()
    {
        // Arrange
        var points = new List<(byte index, byte[] values)>
        {
            (1, new byte[] { 10, 20 }),
            (2, new byte[] { 15, 25, 35 }) // Different length
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            PolynomialInterpolation.Interpolate(0, points));
    }

    [Fact]
    public void Interpolate_DuplicateIndices_ThrowsArgumentException()
    {
        // Arrange
        var points = new List<(byte index, byte[] values)>
        {
            (1, new byte[] { 10 }),
            (1, new byte[] { 20 }) // Duplicate index
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            PolynomialInterpolation.Interpolate(0, points));
    }

    #endregion

    #region Secret Splitting Tests

    [Fact]
    public void SplitSecret_ValidParameters_CreatesCorrectNumberOfShares()
    {
        // Arrange
        var secret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        int threshold = 3;
        int shareCount = 5;

        // Act
        var shares = PolynomialInterpolation.SplitSecret(threshold, shareCount, secret);

        // Assert
        Assert.Equal(shareCount, shares.Length);
        Assert.All(shares, share => Assert.Equal(secret.Length, share.Length));
    }

    [Fact]
    public void SplitSecret_ThresholdOne_AllSharesEqualSecret()
    {
        // Arrange
        var secret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        int threshold = 1;
        int shareCount = 3;

        // Act
        var shares = PolynomialInterpolation.SplitSecret(threshold, shareCount, secret);

        // Assert
        Assert.Equal(shareCount, shares.Length);
        Assert.All(shares, share => Assert.Equal(secret, share));
    }

    [Fact]
    public void SplitSecret_InvalidThreshold_ThrowsArgumentException()
    {
        // Arrange
        var secret = new byte[16];

        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            PolynomialInterpolation.SplitSecret(0, 5, secret)); // threshold <= 0
        
        Assert.Throws<ArgumentException>(() => 
            PolynomialInterpolation.SplitSecret(6, 5, secret)); // threshold > shareCount
    }

    [Fact]
    public void SplitSecret_InvalidShareCount_ThrowsArgumentException()
    {
        // Arrange
        var secret = new byte[16];

        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            PolynomialInterpolation.SplitSecret(3, 17, secret)); // shareCount > 16
    }

    [Fact]
    public void SplitSecret_InvalidSecretLength_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            PolynomialInterpolation.SplitSecret(3, 5, new byte[15])); // < 128 bits
        
        Assert.Throws<ArgumentException>(() => 
            PolynomialInterpolation.SplitSecret(3, 5, new byte[17])); // not multiple of 16 bits
    }

    [Fact]
    public void SplitSecret_NullSecret_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => 
            PolynomialInterpolation.SplitSecret(3, 5, null));
    }

    #endregion

    #region Secret Recovery Tests

    /// <summary>
    /// RecoverSecret zeroes its intermediate buffers in a finally block, and zeroes the
    /// recovered secret too on the failure paths where it never reaches the caller. This
    /// guards the mistake that arrangement invites: clearing the array that was just
    /// returned. A caller that got an all-zero secret back would silently derive the wrong
    /// BIP32 key rather than see an error.
    /// </summary>
    [Fact]
    public void RecoverSecret_ReturnedSecret_IsNotZeroedByTheCleanupPath()
    {
        // Arrange
        var originalSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        int threshold = 3;

        var shares = PolynomialInterpolation.SplitSecret(threshold, 5, originalSecret);
        var sharePoints = shares.Select((share, index) => ((byte)index, share)).Take(threshold).ToList();

        // Act
        var recovered = PolynomialInterpolation.RecoverSecret(threshold, sharePoints);

        // Assert
        Assert.Equal(originalSecret, recovered);
        Assert.Contains(recovered, b => b != 0);
    }

    /// <summary>
    /// The digest comparison uses CryptographicOperations.FixedTimeEquals. This checks the
    /// swap kept the observable contract: a share set that fails validation still raises,
    /// and does so regardless of how many leading digest bytes happen to match.
    /// </summary>
    [Fact]
    public void RecoverSecret_DigestMismatch_ThrowsRegardlessOfLeadingByteAgreement()
    {
        // Arrange
        var originalSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        int threshold = 3;
        var shares = PolynomialInterpolation.SplitSecret(threshold, 5, originalSecret);

        // Corrupt one share; every byte position is exercised so the comparison is forced
        // through both the "differs immediately" and "differs late" cases.
        for (int position = 0; position < originalSecret.Length; position++)
        {
            var corrupted = shares.Select(s => (byte[])s.Clone()).ToArray();
            corrupted[0][position] ^= 0xFF;
            var sharePoints = corrupted.Select((share, index) => ((byte)index, share)).Take(threshold).ToList();

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() =>
                PolynomialInterpolation.RecoverSecret(threshold, sharePoints));
        }
    }

    /// <summary>
    /// With threshold 1 the secret is just the share, and returning the caller's array
    /// directly would alias it. That matters now that the returned buffer is owned — and
    /// eventually zeroed — by the caller: CombineShares zeroes what RecoverSecret gives it,
    /// which for a 1-of-1 group would wipe the ShareValue of a share the caller still holds.
    /// </summary>
    [Fact]
    public void RecoverSecret_ThresholdOne_ReturnsCopyNotAliasOfInputShare()
    {
        // Arrange
        var shareValue = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var sharePoints = new List<(byte, byte[])> { ((byte)0, shareValue) };

        // Act
        var recovered = PolynomialInterpolation.RecoverSecret(1, sharePoints);

        // Assert
        Assert.Equal(shareValue, recovered);
        Assert.NotSame(shareValue, recovered);

        // Mutating the returned buffer, as an owner is entitled to, must not touch the input
        CryptographicOperations.ZeroMemory(recovered);
        Assert.Contains(shareValue, b => b != 0);
    }

    [Fact]
    public void RecoverSecret_ValidShares_RecoversOriginalSecret()
    {
        // Arrange
        var originalSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        int threshold = 3;
        int shareCount = 5;

        var shares = PolynomialInterpolation.SplitSecret(threshold, shareCount, originalSecret);
        var sharePoints = shares.Select((share, index) => ((byte)index, share)).Take(threshold).ToList();

        // Act
        var recoveredSecret = PolynomialInterpolation.RecoverSecret(threshold, sharePoints);

        // Assert
        Assert.Equal(originalSecret, recoveredSecret);
    }

    [Fact]
    public void RecoverSecret_ThresholdOne_ReturnsFirstShare()
    {
        // Arrange
        var secret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var sharePoints = new List<(byte index, byte[] value)> { (0, secret), (1, secret) };

        // Act
        var recovered = PolynomialInterpolation.RecoverSecret(1, sharePoints);

        // Assert
        Assert.Equal(secret, recovered);
    }

    [Fact]
    public void RecoverSecret_DifferentShareCombinations_SameResult()
    {
        // Arrange
        var originalSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        int threshold = 3;
        int shareCount = 5;

        var shares = PolynomialInterpolation.SplitSecret(threshold, shareCount, originalSecret);

        // Create different combinations of shares
        var combination1 = new List<(byte index, byte[] value)>
        {
            (0, shares[0]), (1, shares[1]), (2, shares[2])
        };

        var combination2 = new List<(byte index, byte[] value)>
        {
            (1, shares[1]), (3, shares[3]), (4, shares[4])
        };

        var combination3 = new List<(byte index, byte[] value)>
        {
            (0, shares[0]), (2, shares[2]), (4, shares[4])
        };

        // Act
        var recovered1 = PolynomialInterpolation.RecoverSecret(threshold, combination1);
        var recovered2 = PolynomialInterpolation.RecoverSecret(threshold, combination2);
        var recovered3 = PolynomialInterpolation.RecoverSecret(threshold, combination3);

        // Assert
        Assert.Equal(originalSecret, recovered1);
        Assert.Equal(originalSecret, recovered2);
        Assert.Equal(originalSecret, recovered3);
    }

    [Fact]
    public void RecoverSecret_InsufficientShares_ThrowsArgumentException()
    {
        // Arrange
        var sharePoints = new List<(byte index, byte[] value)>
        {
            (0, new byte[16]), (1, new byte[16])
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            PolynomialInterpolation.RecoverSecret(3, sharePoints)); // need 3, have 2
    }

    [Fact]
    public void RecoverSecret_NullShares_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => 
            PolynomialInterpolation.RecoverSecret(3, null));
    }

    [Fact]
    public void RecoverSecret_CorruptedShare_ThrowsInvalidOperationException()
    {
        // Arrange
        var originalSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        int threshold = 3;
        int shareCount = 5;

        var shares = PolynomialInterpolation.SplitSecret(threshold, shareCount, originalSecret);
        
        // Corrupt one share
        shares[0][0] ^= 1;
        
        var sharePoints = shares.Select((share, index) => ((byte)index, share)).Take(threshold).ToList();

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => 
            PolynomialInterpolation.RecoverSecret(threshold, sharePoints));
    }

    #endregion

    #region Share Validation Tests

    [Fact]
    public void ValidateShares_ValidShares_ReturnsTrue()
    {
        // Arrange
        var shares = new List<(byte index, byte[] value)>
        {
            (0, new byte[16]),
            (1, new byte[16]),
            (2, new byte[16])
        };

        // Act
        var isValid = PolynomialInterpolation.ValidateShares(3, shares);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void ValidateShares_InsufficientShares_ReturnsFalse()
    {
        // Arrange
        var shares = new List<(byte index, byte[] value)>
        {
            (0, new byte[16]),
            (1, new byte[16])
        };

        // Act
        var isValid = PolynomialInterpolation.ValidateShares(3, shares);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void ValidateShares_DuplicateIndices_ReturnsFalse()
    {
        // Arrange
        var shares = new List<(byte index, byte[] value)>
        {
            (0, new byte[16]),
            (1, new byte[16]),
            (1, new byte[16]) // Duplicate index
        };

        // Act
        var isValid = PolynomialInterpolation.ValidateShares(3, shares);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void ValidateShares_DifferentShareLengths_ReturnsFalse()
    {
        // Arrange
        var shares = new List<(byte index, byte[] value)>
        {
            (0, new byte[16]),
            (1, new byte[16]),
            (2, new byte[20]) // Different length
        };

        // Act
        var isValid = PolynomialInterpolation.ValidateShares(3, shares);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void ValidateShares_NullShares_ReturnsFalse()
    {
        // Act
        var isValid = PolynomialInterpolation.ValidateShares(3, null);

        // Assert
        Assert.False(isValid);
    }

    #endregion

    #region Round-trip Tests

    [Fact]
    public void RoundTrip_128BitSecret_3of5_PreservesSecret()
    {
        // Arrange
        var secret = new byte[16];
        for (int i = 0; i < 16; i++) secret[i] = (byte)(i + 1);

        // Act
        var shares = PolynomialInterpolation.SplitSecret(3, 5, secret);
        var sharePoints = shares.Select((share, index) => ((byte)index, share)).Take(3).ToList();
        var recovered = PolynomialInterpolation.RecoverSecret(3, sharePoints);

        // Assert
        Assert.Equal(secret, recovered);
    }

    [Fact]
    public void RoundTrip_256BitSecret_2of3_PreservesSecret()
    {
        // Arrange
        var secret = new byte[32];
        for (int i = 0; i < 32; i++) secret[i] = (byte)(i * 7 % 256);

        // Act
        var shares = PolynomialInterpolation.SplitSecret(2, 3, secret);
        var sharePoints = shares.Select((share, index) => ((byte)index, share)).Take(2).ToList();
        var recovered = PolynomialInterpolation.RecoverSecret(2, sharePoints);

        // Assert
        Assert.Equal(secret, recovered);
    }

    [Fact]
    public void RoundTrip_MaximumShares_16of16_PreservesSecret()
    {
        // Arrange
        var secret = new byte[16];
        for (int i = 0; i < 16; i++) secret[i] = (byte)(255 - i);

        // Act
        var shares = PolynomialInterpolation.SplitSecret(16, 16, secret);
        var sharePoints = shares.Select((share, index) => ((byte)index, share)).ToList();
        var recovered = PolynomialInterpolation.RecoverSecret(16, sharePoints);

        // Assert
        Assert.Equal(secret, recovered);
    }

    [Fact]
    public void RoundTrip_ExtraShares_OnlyThresholdNeeded()
    {
        // Arrange
        var secret = new byte[16];
        for (int i = 0; i < 16; i++) secret[i] = (byte)(i + 100);

        // Act
        var shares = PolynomialInterpolation.SplitSecret(3, 7, secret);
        
        // Use exactly threshold number of shares
        var sharePoints = shares.Select((share, index) => ((byte)index, share)).Take(3).ToList();
        var recovered = PolynomialInterpolation.RecoverSecret(3, sharePoints);

        // Assert
        Assert.Equal(secret, recovered);
    }

    #endregion

    #region Edge Cases

    [Fact]
    public void SplitAndRecover_AllZeroSecret_WorksCorrectly()
    {
        // Arrange
        var secret = new byte[16]; // All zeros

        // Act
        var shares = PolynomialInterpolation.SplitSecret(2, 4, secret);
        var sharePoints = shares.Select((share, index) => ((byte)index, share)).Take(2).ToList();
        var recovered = PolynomialInterpolation.RecoverSecret(2, sharePoints);

        // Assert
        Assert.Equal(secret, recovered);
    }

    [Fact]
    public void SplitAndRecover_AllMaxSecret_WorksCorrectly()
    {
        // Arrange
        var secret = new byte[16];
        Array.Fill(secret, (byte)255);

        // Act
        var shares = PolynomialInterpolation.SplitSecret(2, 4, secret);
        var sharePoints = shares.Select((share, index) => ((byte)index, share)).Take(2).ToList();
        var recovered = PolynomialInterpolation.RecoverSecret(2, sharePoints);

        // Assert
        Assert.Equal(secret, recovered);
    }

    [Fact]
    public void SplitAndRecover_RandomSecret_MultipleRounds()
    {
        // Arrange
        var random = new Random(42); // Fixed seed for reproducibility
        
        for (int round = 0; round < 10; round++)
        {
            var secret = new byte[16];
            random.NextBytes(secret);

            // Act
            var shares = PolynomialInterpolation.SplitSecret(3, 5, secret);
            var sharePoints = shares.Select((share, index) => ((byte)index, share)).Take(3).ToList();
            var recovered = PolynomialInterpolation.RecoverSecret(3, sharePoints);

            // Assert
            Assert.Equal(secret, recovered);
        }
    }

    #endregion
}
