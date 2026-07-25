using System.Security.Cryptography;

namespace Slip39.Core;

/// <summary>
/// Implements polynomial interpolation and Shamir's secret sharing over GF(256).
/// Based on the SLIP-0039 specification for polynomial interpolation using Lagrange formula.
/// </summary>
public static class PolynomialInterpolation
{
    /// <summary>
    /// Performs Lagrange interpolation to compute f(x) given a set of points.
    /// Used in Shamir's secret sharing scheme for both splitting and recovering secrets.
    /// </summary>
    /// <param name="x">The desired index x to evaluate the polynomial at</param>
    /// <param name="points">Set of index/value-vector pairs defining the polynomial</param>
    /// <returns>The value-vector (f₁(x), ..., fₙ(x))</returns>
    /// <exception cref="ArgumentException">Thrown when points are invalid or insufficient</exception>
    public static byte[] Interpolate(byte x, IList<(byte index, byte[] values)> points)
    {
        if (points == null)
            throw new ArgumentNullException(nameof(points));
        
        if (points.Count == 0)
            throw new ArgumentException("At least one point is required for interpolation", nameof(points));

        // Check that all value vectors have the same length
        int valueLength = points[0].values.Length;
        if (points.Any(p => p.values.Length != valueLength))
            throw new ArgumentException("All value vectors must have the same length", nameof(points));

        // Check for duplicate x values
        var xValues = points.Select(p => p.index).ToList();
        if (xValues.Count != xValues.Distinct().Count())
            throw new ArgumentException("All x values must be distinct", nameof(points));

        var result = new byte[valueLength];

        // Apply Lagrange interpolation formula for each byte position
        for (int k = 0; k < valueLength; k++)
        {
            byte sum = 0;

            for (int i = 0; i < points.Count; i++)
            {
                byte xi = points[i].index;
                byte yi = points[i].values[k];

                // Calculate Lagrange basis polynomial L_i(x)
                byte numerator = 1;
                byte denominator = 1;

                for (int j = 0; j < points.Count; j++)
                {
                    if (i == j) continue;

                    byte xj = points[j].index;
                    
                    // numerator *= (x - xj)
                    numerator = GaloisField256.Multiply(numerator, GaloisField256.Subtract(x, xj));
                    
                    // denominator *= (xi - xj)
                    denominator = GaloisField256.Multiply(denominator, GaloisField256.Subtract(xi, xj));
                }

                // Calculate yi * (numerator / denominator)
                byte basis = GaloisField256.Divide(numerator, denominator);
                byte term = GaloisField256.Multiply(yi, basis);
                
                // sum += term
                sum = GaloisField256.Add(sum, term);
            }

            result[k] = sum;
        }

        return result;
    }

    /// <summary>
    /// Splits a secret into N shares using Shamir's secret sharing scheme.
    /// Implements the SplitSecret algorithm from SLIP-0039 specification.
    /// </summary>
    /// <param name="threshold">Number of shares required to reconstruct the secret (T)</param>
    /// <param name="shareCount">Total number of shares to generate (N)</param>
    /// <param name="secret">The secret to split</param>
    /// <returns>Array of shares for indices 0 through N-1</returns>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid</exception>
    public static byte[][] SplitSecret(int threshold, int shareCount, byte[] secret)
    {
        if (secret == null)
            throw new ArgumentNullException(nameof(secret));
        
        // Check conditions from SLIP-0039 specification
        if (threshold <= 0 || threshold > shareCount || shareCount > 16)
            throw new ArgumentException("Invalid threshold or share count: 0 < T ≤ N ≤ 16");
        
        if (secret.Length < 16 || secret.Length % 2 != 0)
            throw new ArgumentException("Secret length must be at least 128 bits and a multiple of 16 bits");

        // Special case: if threshold is 1, all shares are the secret
        if (threshold == 1)
        {
            var shares = new byte[shareCount][];
            for (int i = 0; i < shareCount; i++)
            {
                shares[i] = new byte[secret.Length];
                Array.Copy(secret, shares[i], secret.Length);
            }
            return shares;
        }

        int n = secret.Length;
        
        // Generate digest D (first 4 bytes are HMAC of secret with random key R)
        using var rng = RandomNumberGenerator.Create();
        var R = new byte[Math.Max(0, n - 4)];
        rng.GetBytes(R);
        
        byte[] D = GenerateDigest(secret, R);
        
        // Generate T-2 random shares
        var randomShares = new List<byte[]>();
        for (int i = 0; i < threshold - 2; i++)
        {
            var randomShare = new byte[n];
            rng.GetBytes(randomShare);
            randomShares.Add(randomShare);
        }

        // Create all shares
        var allShares = new byte[shareCount][];
        
        // First T-2 shares are random
        for (int i = 0; i < threshold - 2; i++)
        {
            allShares[i] = randomShares[i];
        }
        
        // Remaining shares are computed using interpolation
        for (int i = threshold - 2; i < shareCount; i++)
        {
            // Build points list for interpolation at index i
            var points = new List<(byte index, byte[] values)>();
            
            // Add the random shares (indices 0 to T-3)
            for (int j = 0; j < threshold - 2; j++)
            {
                points.Add(((byte)j, randomShares[j]));
            }
            
            // Add fixed points: (254, D) and (255, S)
            points.Add((254, D));
            points.Add((255, secret));
            
            // Interpolate to get share at index i
            allShares[i] = Interpolate((byte)i, points);
        }

        return allShares;
    }

    /// <summary>
    /// Recovers a secret from a set of shares using Shamir's secret sharing scheme.
    /// Implements the RecoverSecret algorithm from SLIP-0039 specification.
    /// </summary>
    /// <param name="threshold">The threshold used when splitting the secret</param>
    /// <param name="shares">List of share index/value pairs</param>
    /// <returns>The recovered secret</returns>
    /// <exception cref="ArgumentException">Thrown when shares are invalid or insufficient</exception>
    /// <exception cref="InvalidOperationException">Thrown when secret validation fails</exception>
    public static byte[] RecoverSecret(int threshold, IList<(byte index, byte[] value)> shares)
    {
        if (shares == null)
            throw new ArgumentNullException(nameof(shares));
        
        if (shares.Count < threshold)
            throw new ArgumentException($"Insufficient shares: need {threshold}, got {shares.Count}");

        // Special case: if threshold is 1, return any share
        if (threshold == 1)
        {
            return shares.First().value;
        }

        // Use only the first 'threshold' shares for interpolation
        var selectedShares = shares.Take(threshold).ToList();

        // Recover the secret at f(255)
        byte[] recoveredSecret = Interpolate(255, selectedShares);
        
        // Recover the digest at f(254) for validation
        byte[] recoveredDigest = Interpolate(254, selectedShares);
        
        // Validate the secret using the digest
        if (recoveredDigest.Length < 4)
            throw new InvalidOperationException("Invalid digest length");
            
        byte[] R = new byte[recoveredDigest.Length - 4];
        Array.Copy(recoveredDigest, 4, R, 0, R.Length);
        
        byte[] expectedDigest = GenerateDigest(recoveredSecret, R);
        
        // Compare first 4 bytes of the digests
        for (int i = 0; i < 4; i++)
        {
            if (recoveredDigest[i] != expectedDigest[i])
                throw new InvalidOperationException("Secret validation failed: digest mismatch");
        }

        return recoveredSecret;
    }

    /// <summary>
    /// Generates a digest for secret validation as specified in SLIP-0039.
    /// The digest consists of the first 4 bytes of HMAC-SHA256(key=R, msg=S) concatenated with R.
    /// </summary>
    /// <param name="secret">The secret to generate digest for</param>
    /// <param name="randomKey">The random key R</param>
    /// <returns>The digest D = HMAC₄(R, S) || R</returns>
    private static byte[] GenerateDigest(byte[] secret, byte[] randomKey)
    {
        using var hmac = new HMACSHA256(randomKey);
        byte[] hash = hmac.ComputeHash(secret);
        
        var digest = new byte[4 + randomKey.Length];
        Array.Copy(hash, 0, digest, 0, 4);  // First 4 bytes of HMAC
        Array.Copy(randomKey, 0, digest, 4, randomKey.Length);  // R
        
        return digest;
    }

    /// <summary>
    /// Validates that a set of shares can be used for secret recovery.
    /// Checks for duplicate indices and sufficient share count.
    /// </summary>
    /// <param name="threshold">Required threshold</param>
    /// <param name="shares">Shares to validate</param>
    /// <returns>True if shares are valid for recovery</returns>
    public static bool ValidateShares(int threshold, IList<(byte index, byte[] value)> shares)
    {
        if (shares == null || shares.Count < threshold)
            return false;

        // Check for duplicate indices
        var indices = shares.Select(s => s.index).ToList();
        if (indices.Count != indices.Distinct().Count())
            return false;

        // Check that all shares have the same length
        if (shares.Count > 0)
        {
            int expectedLength = shares[0].value.Length;
            if (shares.Any(s => s.value.Length != expectedLength))
                return false;
        }

        return true;
    }
}
