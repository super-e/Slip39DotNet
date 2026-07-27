using Slip39.Core;

namespace Slip39.Core.Tests;

/// <summary>
/// Covers the SLIP-0039 rule that a group must be combined with exactly its member threshold,
/// and the verification path that exists so surplus shares can still be checked.
/// </summary>
public class ShareVerificationTests
{
    const string Passphrase = "pw";
    static readonly byte[] Secret = Convert.FromHexString("00112233445566778899aabbccddeeff");

    static List<Slip39Share> Generate(int memberThreshold, int memberCount) =>
        Slip39ShareGeneration.GenerateShares(
            1,
            new List<Slip39ShareGeneration.GroupConfig> { new(memberThreshold, memberCount) },
            Secret, Passphrase, 0, true);

    /// <summary>
    /// A share carrying the header of <paramref name="template"/> but the wrong value — what a
    /// share that was mis-transcribed at some earlier point looks like. Any altered value is
    /// off the group's polynomial, since the polynomial takes exactly one value at each index.
    /// </summary>
    static Slip39Share Corrupt(Slip39Share template)
    {
        var wrongValue = (byte[])template.ShareValue.Clone();
        wrongValue[0] ^= 0xFF;

        return new Slip39Share(
            template.Identifier, template.IsExtendable, template.IterationExponent,
            template.GroupIndex, template.GroupThreshold, template.GroupCount,
            template.MemberIndex, template.MemberThreshold,
            wrongValue, template.Checksum);
    }

    // ------------------------------------------------------- CombineShares is now strict

    [Fact]
    public void CombineShares_MoreSharesThanTheThreshold_IsRejected()
    {
        var shares = Generate(2, 3);

        // Previously accepted: the third share was dropped by RecoverSecret's Take(threshold)
        // without ever being examined.
        var ex = Assert.Throws<ArgumentException>(
            () => Slip39ShareCombination.CombineShares(shares.ToList(), Passphrase));

        Assert.Contains("exactly 2", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CombineShares_ExactlyTheThreshold_StillRecoversTheSecret()
    {
        var shares = Generate(2, 3);

        var recovered = Slip39ShareCombination.CombineShares(
            new List<Slip39Share> { shares[0], shares[1] }, Passphrase);

        Assert.Equal(Secret, recovered);
    }

    [Fact]
    public void CombineShares_FewerSharesThanTheThreshold_IsStillRejected()
    {
        var shares = Generate(2, 3);

        Assert.Throws<ArgumentException>(
            () => Slip39ShareCombination.CombineShares(new List<Slip39Share> { shares[0] }, Passphrase));
    }

    // ------------------------------------------------------------------- VerifyShares

    [Fact]
    public void VerifyShares_EveryShareIntact_ReportsAllConsistent()
    {
        var report = Slip39ShareCombination.VerifyShares(Generate(2, 3).ToList());

        Assert.True(report.AllConsistent);
        Assert.Equal(3, report.Results.Count);
        Assert.All(report.Results, r => Assert.Equal(ShareStatus.Consistent, r.Status));
    }

    [Fact]
    public void VerifyShares_CorruptShareBeyondTheThreshold_NamesThatShare()
    {
        // This is the case that used to pass silently: the bad share sat past the threshold,
        // so recovery discarded it and reported success.
        var shares = Generate(2, 3);
        var tampered = new List<Slip39Share> { shares[0], shares[1], Corrupt(shares[2]) };

        var report = Slip39ShareCombination.VerifyShares(tampered);

        Assert.False(report.AllConsistent);
        var bad = Assert.Single(report.Inconsistent);
        Assert.Equal(shares[2].MemberIndex, bad.Share.MemberIndex);
    }

    [Fact]
    public void VerifyShares_CorruptShareInsideTheThreshold_StillNamesThatShare()
    {
        // The bad share is now first, so the naive "take the first T as reference" approach
        // would fit a polynomial through corrupt data and flag the two good shares instead.
        // The subset search finds the pair that passes the digest check and gets it right.
        var shares = Generate(2, 3);
        var tampered = new List<Slip39Share> { Corrupt(shares[0]), shares[1], shares[2] };

        var report = Slip39ShareCombination.VerifyShares(tampered);

        Assert.False(report.AllConsistent);
        var bad = Assert.Single(report.Inconsistent);
        Assert.Equal(shares[0].MemberIndex, bad.Share.MemberIndex);
    }

    [Fact]
    public void VerifyShares_NoQuorumSurvives_ReportsTheWholeGroup()
    {
        // Only one good share left in a 2-of-3: no pair passes the digest check, so there is
        // no trustworthy reference and saying which share is at fault would be guesswork.
        var shares = Generate(2, 3);
        var tampered = new List<Slip39Share> { shares[0], Corrupt(shares[1]), Corrupt(shares[2]) };

        var report = Slip39ShareCombination.VerifyShares(tampered);

        Assert.False(report.AllConsistent);
        Assert.Equal(3, report.Inconsistent.Count());
        Assert.All(report.Inconsistent, r =>
            Assert.Contains("no quorum in this group can be trusted", r.Detail, StringComparison.Ordinal));
    }

    [Fact]
    public void VerifyShares_CorruptShareAnywhereInALargerGroup_IsNamed()
    {
        var shares = Generate(3, 5);

        for (int position = 0; position < 5; position++)
        {
            var tampered = shares.ToList();
            tampered[position] = Corrupt(shares[position]);

            var report = Slip39ShareCombination.VerifyShares(tampered);

            Assert.False(report.AllConsistent);
            var bad = Assert.Single(report.Inconsistent);
            Assert.Equal(shares[position].MemberIndex, bad.Share.MemberIndex);
        }
    }

    [Fact]
    public void VerifyShares_FewerSharesThanTheThreshold_ReportsUnverifiable()
    {
        var shares = Generate(3, 5);

        var report = Slip39ShareCombination.VerifyShares(new List<Slip39Share> { shares[0], shares[1] });

        Assert.Equal(2, report.Unverifiable.Count());
        Assert.All(report.Results, r => Assert.Equal(ShareStatus.Unverifiable, r.Status));

        // Nothing was found wrong, but that is not the same as the backup being sound.
        Assert.True(report.AllConsistent);
    }

    [Fact]
    public void VerifyShares_LeavesTheCallersSharesIntact()
    {
        var shares = Generate(2, 3);
        var before = shares.Select(s => (byte[])s.ShareValue.Clone()).ToList();

        Slip39ShareCombination.VerifyShares(shares.ToList());

        for (int i = 0; i < shares.Count; i++)
        {
            Assert.Equal(before[i], shares[i].ShareValue);
        }
    }

    [Fact]
    public void VerifyShares_AcrossMultipleGroups_ChecksEachGroupSeparately()
    {
        var shares = Slip39ShareGeneration.GenerateShares(
            2,
            new List<Slip39ShareGeneration.GroupConfig> { new(2, 3), new(2, 3) },
            Secret, Passphrase, 0, true);

        var report = Slip39ShareCombination.VerifyShares(shares.ToList());

        Assert.True(report.AllConsistent);
        Assert.Equal(6, report.Results.Count);
    }

    [Fact]
    public void VerifyShares_RejectsSharesFromDifferentSets()
    {
        var first = Generate(2, 3);
        var second = Generate(2, 3);

        Assert.Throws<ArgumentException>(
            () => Slip39ShareCombination.VerifyShares(new List<Slip39Share> { first[0], second[1] }));
    }
}
