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
            
            // Member count must equal the member threshold. SLIP-0039 "Combining the shares",
            // check 1: "their count M_i MUST be equal to T_i".
            //
            // Rejecting a surplus rather than trimming it is the point. RecoverSecret only
            // consumes the first T shares, so anything beyond that used to be dropped without
            // ever being looked at: hand a group two good shares and one that had rotted and
            // the recovery reported success, having silently ignored the bad one. Whether the
            // corruption was noticed came down to where in the list it happened to sit.
            //
            // Callers who want to check every share they hold should use VerifyShares, which
            // accepts a surplus precisely so it can test each one against the others.
            int memberCount = groupShares.Count;
            int memberThreshold = firstGroupShare.ActualMemberThreshold;

            if (memberCount < memberThreshold)
                throw new ArgumentException($"Insufficient member shares for group {kvp.Key}: need {memberThreshold}, got {memberCount}");

            if (memberCount > memberThreshold)
                throw new ArgumentException(
                    $"Too many member shares for group {kvp.Key}: need exactly {memberThreshold}, got {memberCount}. " +
                    $"SLIP-0039 requires exactly the threshold; the extra shares would be discarded unverified. " +
                    $"Use {nameof(Slip39ShareCombination)}.{nameof(VerifyShares)} to check every share you hold.");
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
    /// Checks every supplied share against the others in its group, instead of using only as
    /// many as the threshold requires.
    /// </summary>
    /// <param name="shares">
    /// The shares to check. Unlike <see cref="CombineShares"/> this accepts more shares per
    /// group than the member threshold — that is the whole point of the method.
    /// </param>
    /// <returns>A per-share report.</returns>
    /// <remarks>
    /// <para>
    /// Answers the question "are the shares in my backup still intact?", which recovery alone
    /// cannot: recovery consumes exactly the threshold and never looks at the rest.
    /// </para>
    /// <para>
    /// The shares of a group are points on one polynomial of degree T-1, so any T of them fix
    /// it and every remaining share must land on it. Each group is checked by finding a subset
    /// of T shares that passes the SLIP-0039 digest check — the search matters, because any T
    /// shares agree with themselves and only the digest distinguishes the real polynomial from
    /// one fitted through corrupt points — and then evaluating that polynomial at the member
    /// index of every remaining share.
    /// </para>
    /// <para>
    /// Corrupt shares are therefore named individually wherever a valid quorum survives,
    /// regardless of where in the list they appear. Only when no T of the supplied shares
    /// validate together is the whole group reported as inconsistent, which is the honest
    /// answer: in that case nothing in the group can be trusted to measure the rest against.
    /// </para>
    /// <para>
    /// This method does not need and never derives the master secret, so no passphrase is
    /// required and nothing recoverable is returned.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="shares"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when the shares do not form a coherent set.</exception>
    public static ShareVerificationReport VerifyShares(List<Slip39Share> shares)
    {
        if (shares == null)
            throw new ArgumentNullException(nameof(shares));

        if (shares.Count == 0)
            throw new ArgumentException("At least one share is required", nameof(shares));

        ValidateCommonHeaderFields(shares);

        var results = new List<ShareVerification>();

        foreach (var group in shares.GroupBy(s => s.GroupIndex).OrderBy(g => g.Key))
        {
            var groupShares = group.ToList();
            int threshold = groupShares[0].ActualMemberThreshold;

            if (groupShares.Any(s => s.MemberThreshold != groupShares[0].MemberThreshold))
                throw new ArgumentException("All shares in the same group must have the same member threshold", nameof(shares));

            var memberIndices = groupShares.Select(s => s.MemberIndex).ToList();
            if (memberIndices.Count != memberIndices.Distinct().Count())
                throw new ArgumentException("Member indices within a group must be pairwise distinct", nameof(shares));

            if (groupShares.Count < threshold)
            {
                foreach (var share in groupShares)
                {
                    results.Add(new ShareVerification(share, ShareStatus.Unverifiable,
                        $"Group {group.Key} holds {groupShares.Count} of the {threshold} shares needed to check anything."));
                }
                continue;
            }

            results.AddRange(VerifyGroup(group.Key, groupShares, threshold));
        }

        return new ShareVerificationReport(results);
    }

    /// <summary>
    /// Verifies one group whose share count is at least its member threshold.
    /// </summary>
    /// <remarks>
    /// The reference subset is searched for rather than assumed. Taking the first T shares
    /// works only when they happen to be the intact ones: if a bad share sits among them the
    /// digest check fails and the good shares are the ones that look wrong, which is precisely
    /// backwards. Any T shares define a polynomial through themselves, so agreement alone
    /// cannot tell a good subset from a bad one — the SLIP-0039 digest can, and a wrong subset
    /// passes it with probability 2⁻³². The first subset that validates is therefore the real
    /// polynomial, and the shares lying on it are the intact ones.
    ///
    /// Member indices are 4 bits, so a group holds at most 16 shares and the search is
    /// bounded by C(16,8) = 12870 candidates.
    /// </remarks>
    private static List<ShareVerification> VerifyGroup(byte groupIndex, List<Slip39Share> groupShares, int threshold)
    {
        var results = new List<ShareVerification>();

        var reference = FindValidatingSubset(groupShares, threshold);

        if (reference == null)
        {
            foreach (var share in groupShares)
            {
                results.Add(new ShareVerification(share, ShareStatus.Inconsistent,
                    $"No {threshold} of the {groupShares.Count} shares supplied for group {groupIndex} pass the " +
                    $"SLIP-0039 digest check together, so no quorum in this group can be trusted."));
            }
            return results;
        }

        var referenceIndices = reference.Select(p => p.index).ToHashSet();

        foreach (var share in groupShares)
        {
            if (referenceIndices.Contains(share.MemberIndex))
            {
                results.Add(new ShareVerification(share, ShareStatus.Consistent,
                    $"Part of a set of {threshold} shares in group {groupIndex} that passes the digest check."));
                continue;
            }

            byte[] expected = PolynomialInterpolation.Interpolate(share.MemberIndex, reference);
            try
            {
                bool matches = CryptographicOperations.FixedTimeEquals(expected, share.ShareValue);

                results.Add(matches
                    ? new ShareVerification(share, ShareStatus.Consistent,
                        $"Matches the value the other shares of group {groupIndex} predict for member index {share.MemberIndex}.")
                    : new ShareVerification(share, ShareStatus.Inconsistent,
                        $"Does not match the value the other shares of group {groupIndex} predict for member index {share.MemberIndex}."));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expected);
            }
        }

        // If the shares that disagreed contain a validating quorum of their own, the set
        // describes two different secrets and picking either would be arbitrary. The first
        // subset to validate is the real polynomial only when there is one real polynomial;
        // reporting a winner here would mean silently recovering whichever secret happened
        // to be found first.
        var dissenting = results
            .Where(r => r.Status == ShareStatus.Inconsistent)
            .Select(r => r.Share)
            .ToList();

        if (dissenting.Count >= threshold && FindValidatingSubset(dissenting, threshold) != null)
        {
            return groupShares
                .Select(share => new ShareVerification(share, ShareStatus.Inconsistent,
                    $"Group {groupIndex} contains two sets of shares that each reconstruct a secret, " +
                    $"but different ones. These shares do not all come from the same backup, and no " +
                    $"choice between them can be made here."))
                .ToList();
        }

        return results;
    }

    /// <summary>
    /// Finds a subset of exactly <paramref name="threshold"/> shares that passes the
    /// SLIP-0039 digest check, or null when no such subset exists.
    /// </summary>
    private static List<(byte index, byte[] values)>? FindValidatingSubset(
        List<Slip39Share> groupShares, int threshold)
    {
        var candidates = Combinations(groupShares.Count, threshold)
            .Select(combination => combination
                .Select(i => (groupShares[i].MemberIndex, groupShares[i].ShareValue))
                .ToList());

        foreach (var candidate in candidates)
        {
            try
            {
                byte[] groupSecret = PolynomialInterpolation.RecoverSecret(threshold, candidate);
                CryptographicOperations.ZeroMemory(groupSecret);
                return candidate.Select(p => (p.MemberIndex, p.ShareValue)).ToList();
            }
            catch (InvalidOperationException)
            {
                // This subset does not lie on a common polynomial with a valid digest;
                // at least one of its shares is wrong. Try the next.
            }
        }

        return null;
    }

    /// <summary>
    /// Enumerates every way of choosing <paramref name="k"/> of <paramref name="n"/> indices,
    /// in lexicographic order.
    /// </summary>
    private static IEnumerable<int[]> Combinations(int n, int k)
    {
        if (k > n || k <= 0)
            yield break;

        var indices = Enumerable.Range(0, k).ToArray();

        while (true)
        {
            yield return (int[])indices.Clone();

            int i = k - 1;
            while (i >= 0 && indices[i] == i + n - k)
                i--;

            if (i < 0)
                yield break;

            indices[i]++;
            for (int j = i + 1; j < k; j++)
                indices[j] = indices[j - 1] + 1;
        }
    }

    /// <summary>
    /// Checks the fields that must agree across every share of a set.
    /// </summary>
    private static void ValidateCommonHeaderFields(List<Slip39Share> shares)
    {
        var firstShare = shares[0];

        foreach (var share in shares)
        {
            if (share.Identifier != firstShare.Identifier)
                throw new ArgumentException("All shares must have the same identifier", nameof(shares));

            if (share.IsExtendable != firstShare.IsExtendable)
                throw new ArgumentException("All shares must have the same extendable backup flag", nameof(shares));

            if (share.IterationExponent != firstShare.IterationExponent)
                throw new ArgumentException("All shares must have the same iteration exponent", nameof(shares));

            if (share.GroupThreshold != firstShare.GroupThreshold)
                throw new ArgumentException("All shares must have the same group threshold", nameof(shares));

            if (share.GroupCount != firstShare.GroupCount)
                throw new ArgumentException("All shares must have the same group count", nameof(shares));

            if (share.ShareValue.Length != firstShare.ShareValue.Length)
                throw new ArgumentException("All shares must have the same length", nameof(shares));
        }
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
            // Encode the share exactly as ToMnemonic does. This used to go through a local
            // copy of that logic; two hand-maintained copies of the share bit layout is the
            // shape of the ToHex/ParseFromHex defect, so there is now only one.
            var shareWords = Array.ConvertAll(Slip39ShareParser.ShareToIndices(share), i => (ushort)i);
            
            // Verify the RS1024 checksum
            if (!Rs1024Checksum.VerifyChecksum(shareWords, share.IsExtendable))
            {
                throw new ArgumentException($"Invalid checksum for share with identifier {share.Identifier}");
            }
        }
    }
    
}

/// <summary>
/// The outcome of checking one share against the others in its group.
/// </summary>
public enum ShareStatus
{
    /// <summary>The share agrees with the others in its group.</summary>
    Consistent,

    /// <summary>
    /// The share does not lie on the polynomial that the intact shares of its group define,
    /// so this share is wrong. When no quorum of the group validates at all, every share in
    /// it is marked this way instead — nothing there can be trusted.
    /// </summary>
    Inconsistent,

    /// <summary>
    /// Nothing could be determined: the group holds fewer shares than its member threshold,
    /// so there is no polynomial to check against.
    /// </summary>
    Unverifiable
}

/// <summary>
/// The verdict on a single share.
/// </summary>
/// <param name="Share">The share that was checked.</param>
/// <param name="Status">Whether it agrees with the others in its group.</param>
/// <param name="Detail">A human-readable explanation of the verdict.</param>
public sealed record ShareVerification(Slip39Share Share, ShareStatus Status, string Detail);

/// <summary>
/// The result of <see cref="Slip39ShareCombination.VerifyShares"/>.
/// </summary>
/// <param name="Results">One entry per supplied share, grouped by group index.</param>
public sealed record ShareVerificationReport(IReadOnlyList<ShareVerification> Results)
{
    /// <summary>True when no share was found to disagree with its group.</summary>
    /// <remarks>
    /// Shares that could not be checked at all do not make this false — check
    /// <see cref="Unverifiable"/> as well before concluding a backup is sound.
    /// </remarks>
    public bool AllConsistent => Results.All(r => r.Status != ShareStatus.Inconsistent);

    /// <summary>The shares that disagree with their group.</summary>
    public IEnumerable<ShareVerification> Inconsistent =>
        Results.Where(r => r.Status == ShareStatus.Inconsistent);

    /// <summary>The shares whose group was too small to check.</summary>
    public IEnumerable<ShareVerification> Unverifiable =>
        Results.Where(r => r.Status == ShareStatus.Unverifiable);
}
