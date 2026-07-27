using Slip39.Core;

namespace Slip39.Console.Tests;

/// <summary>
/// End-to-end tests for the command line interface.
/// </summary>
public class ProgramTests
{
    const string Secret = "00112233445566778899aabbccddeeff";

    /// <summary>A deterministic mainnet xprv, derived from a fixed seed.</summary>
    static string SampleXprv()
    {
        var seed = new byte[32];
        for (int i = 0; i < seed.Length; i++) seed[i] = (byte)(i + 1);
        return Bip32MasterKey.GenerateMasterKey(seed);
    }

    /// <summary>Pulls the mnemonics out of a 'split'/'generate' text report.</summary>
    static List<string> ExtractMnemonics(string output) =>
        output.Split('\n')
              .Select(l => l.Trim())
              .Where(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length >= 20)
              .ToList();

    // ---------------------------------------------------------------- exit codes

    public static TheoryData<string[]> FailingInvocations => new()
    {
        new[] { "combine", "this is not a valid share mnemonic at all" },
        new[] { "split", "--secret", "ZZZZ" },
        new[] { "split", "--threshold", "2" },                  // --secret missing
        new[] { "generate", "--bits", "77" },
        new[] { "info", "too short to be a share" },
        new[] { "not-a-command" },
    };

    [Theory]
    [MemberData(nameof(FailingInvocations))]
    public void FailingCommands_ExitNonZero(string[] args)
    {
        var result = CliRunner.Run(args);

        Assert.Equal(Program.ExitFailure, result.ExitCode);
    }

    [Theory]
    [MemberData(nameof(FailingInvocations))]
    public void FailingCommands_ReportOnStandardError(string[] args)
    {
        var result = CliRunner.Run(args);

        // A message on stdout is invisible to `cmd 2>errors.log` and mixes into piped output.
        Assert.NotEqual("", result.StdErr.Trim());
    }

    [Fact]
    public void Help_Succeeds()
    {
        Assert.Equal(Program.ExitSuccess, CliRunner.Run("help").ExitCode);
        Assert.Equal(Program.ExitSuccess, CliRunner.Run().ExitCode);
    }

    // ---------------------------------------------------- unknown options are fatal

    [Theory]
    [InlineData("split", "--treshold")]
    [InlineData("generate", "--bitz")]
    [InlineData("combine", "--passphrasse")]
    [InlineData("validate", "--verbse")]
    [InlineData("info", "--frmat")]
    [InlineData("split-xpriv", "--xprv")]
    public void MisspelledOption_IsRejected(string command, string option)
    {
        // Silently ignoring an unknown option let `split --treshold 5 --shares 7` produce a
        // 2-of-7 split: the user asked for a 5-of-7 and got weaker parameters with no warning.
        var result = CliRunner.Run(command, option, "5");

        Assert.Equal(Program.ExitFailure, result.ExitCode);
        Assert.Contains(option, result.StdErr, StringComparison.Ordinal);
    }

    [Fact]
    public void MisspelledThreshold_DoesNotSilentlyProduceADifferentSplit()
    {
        var result = CliRunner.Run("split", "--secret", Secret, "--treshold", "5", "--shares", "7");

        Assert.Equal(Program.ExitFailure, result.ExitCode);
        Assert.Empty(ExtractMnemonics(result.StdOut));
    }

    // ------------------------------------------------------------- split / combine

    [Fact]
    public void Split_ThenCombine_RecoversTheSecret()
    {
        var split = CliRunner.Run("split", "--secret", Secret, "--threshold", "2", "--shares", "3");
        Assert.Equal(Program.ExitSuccess, split.ExitCode);

        var mnemonics = ExtractMnemonics(split.StdOut);
        Assert.Equal(3, mnemonics.Count);

        var combine = CliRunner.Run("combine", mnemonics[0], mnemonics[1]);

        Assert.Equal(Program.ExitSuccess, combine.ExitCode);
        Assert.Contains(Secret, combine.StdOut, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Split_HonoursTheRequestedThreshold()
    {
        var split = CliRunner.Run("split", "--secret", Secret, "--threshold", "3", "--shares", "5");
        var mnemonics = ExtractMnemonics(split.StdOut);
        Assert.Equal(5, mnemonics.Count);

        // Two shares must not be enough for a 3-of-5.
        var tooFew = CliRunner.Run("combine", mnemonics[0], mnemonics[1]);
        Assert.Equal(Program.ExitFailure, tooFew.ExitCode);

        var enough = CliRunner.Run("combine", mnemonics[0], mnemonics[1], mnemonics[2]);
        Assert.Equal(Program.ExitSuccess, enough.ExitCode);
        Assert.Contains(Secret, enough.StdOut, StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------------- info

    [Fact]
    public void Info_AcceptsOptionsBeforeTheShare()
    {
        var mnemonic = ExtractMnemonics(
            CliRunner.Run("split", "--secret", Secret, "--threshold", "1", "--shares", "1").StdOut)[0];

        // This is the invocation the built-in help documents.
        var result = CliRunner.Run("info", "--format", "json", mnemonic);

        Assert.Equal(Program.ExitSuccess, result.ExitCode);
        Assert.Contains("\"identifier\"", result.StdOut, StringComparison.Ordinal);
    }

    [Fact]
    public void Info_AcceptsOptionsAfterTheShare()
    {
        var mnemonic = ExtractMnemonics(
            CliRunner.Run("split", "--secret", Secret, "--threshold", "1", "--shares", "1").StdOut)[0];

        var result = CliRunner.Run("info", mnemonic, "--format", "json");

        Assert.Equal(Program.ExitSuccess, result.ExitCode);
        Assert.Contains("\"identifier\"", result.StdOut, StringComparison.Ordinal);
    }

    // --------------------------------------------------------------- split-xpriv

    [Fact]
    public void SplitXpriv_WithoutShowSecret_DoesNotPrintKeyMaterial()
    {
        string xprv = SampleXprv();
        byte[] raw = Base58Check.Decode(xprv);
        string privateKeyHex = Convert.ToHexString(raw.AsSpan(46, 32)).ToLowerInvariant();
        string chainCodeHex = Convert.ToHexString(raw.AsSpan(13, 32)).ToLowerInvariant();

        var result = CliRunner.Run("split-xpriv", "--xpriv", xprv, "--threshold", "2", "--shares", "3");

        Assert.Equal(Program.ExitSuccess, result.ExitCode);
        Assert.DoesNotContain(privateKeyHex, result.Combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(chainCodeHex, result.Combined, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(3, ExtractMnemonics(result.StdOut).Count);
    }

    [Fact]
    public void SplitXpriv_WithShowSecret_PrintsKeyMaterial()
    {
        string xprv = SampleXprv();
        string privateKeyHex = Convert.ToHexString(Base58Check.Decode(xprv).AsSpan(46, 32)).ToLowerInvariant();

        var result = CliRunner.Run("split-xpriv", "--xpriv", xprv, "--show-secret");

        Assert.Equal(Program.ExitSuccess, result.ExitCode);
        Assert.Contains(privateKeyHex, result.StdOut, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SplitXpriv_ExtendedPublicKey_IsRejected()
    {
        // An xpub decodes to 78 bytes and used to pass with only a warning, after which the
        // command printed part of the public key labelled "Private Key" and split it.
        const string Xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

        var result = CliRunner.Run("split-xpriv", "--xpriv", Xpub, "--threshold", "2", "--shares", "3");

        Assert.Equal(Program.ExitFailure, result.ExitCode);
        Assert.DoesNotContain("Private Key", result.Combined, StringComparison.Ordinal);
        Assert.Empty(ExtractMnemonics(result.StdOut));
    }

    // -------------------------------------------------- surplus shares get verified

    /// <summary>
    /// Builds a mnemonic that parses and checksums cleanly but carries the wrong share value —
    /// what a share mis-transcribed at some earlier point looks like by the time it is typed
    /// back in. A plain typo would be caught by RS1024; this is the case that would not be.
    /// </summary>
    static string ForgeShareWithForeignValue(Slip39Share template, byte[] foreignValue)
    {
        var draft = new Slip39Share(
            template.Identifier, template.IsExtendable, template.IterationExponent,
            template.GroupIndex, template.GroupThreshold, template.GroupCount,
            template.MemberIndex, template.MemberThreshold, foreignValue, 0);

        var indices = Slip39ShareParser.ShareToIndices(draft);
        var data = indices.Take(indices.Length - 3).Select(i => (ushort)i).ToArray();
        var words = Rs1024Checksum.GenerateChecksum(data, template.IsExtendable);
        uint checksum = ((uint)words[0] << 20) | ((uint)words[1] << 10) | words[2];

        return new Slip39Share(
            template.Identifier, template.IsExtendable, template.IterationExponent,
            template.GroupIndex, template.GroupThreshold, template.GroupCount,
            template.MemberIndex, template.MemberThreshold, foreignValue, checksum).ToMnemonic();
    }

    [Fact]
    public void Combine_MoreSharesThanTheThreshold_ChecksThemAndStillRecovers()
    {
        var mnemonics = ExtractMnemonics(
            CliRunner.Run("split", "--secret", Secret, "--threshold", "2", "--shares", "3").StdOut);

        var result = CliRunner.Run("combine", mnemonics[0], mnemonics[1], mnemonics[2]);

        Assert.Equal(Program.ExitSuccess, result.ExitCode);
        Assert.Contains(Secret, result.StdOut, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("agrees with the others", result.StdOut, StringComparison.Ordinal);
    }

    [Fact]
    public void Combine_SurplusShareCarryingTheWrongValue_RefusesToRecover()
    {
        var good = ExtractMnemonics(
            CliRunner.Run("split", "--secret", Secret, "--threshold", "2", "--shares", "3").StdOut);
        var other = ExtractMnemonics(
            CliRunner.Run("split", "--secret", "ffeeddccbbaa99887766554433221100", "--threshold", "2", "--shares", "3").StdOut);

        var template = Slip39ShareParser.ParseFromMnemonic(good[2]);
        var foreign = Slip39ShareParser.ParseFromMnemonic(other[2]).ShareValue;
        string forged = ForgeShareWithForeignValue(template, foreign);

        // The first two shares alone would recover the secret, and the bad third one sits
        // past the threshold — exactly the arrangement that used to report success.
        var result = CliRunner.Run("combine", good[0], good[1], forged);

        Assert.Equal(Program.ExitFailure, result.ExitCode);
        Assert.Contains("do not agree", result.StdErr, StringComparison.Ordinal);
        Assert.Contains($"member {template.MemberIndex}", result.StdErr, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, result.Combined, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Combine_IgnoreInvalidShares_RecoversFromTheSoundOnes()
    {
        var good = ExtractMnemonics(
            CliRunner.Run("split", "--secret", Secret, "--threshold", "2", "--shares", "3").StdOut);
        var other = ExtractMnemonics(
            CliRunner.Run("split", "--secret", "ffeeddccbbaa99887766554433221100", "--threshold", "2", "--shares", "3").StdOut);

        var template = Slip39ShareParser.ParseFromMnemonic(good[2]);
        var foreign = Slip39ShareParser.ParseFromMnemonic(other[2]).ShareValue;
        string forged = ForgeShareWithForeignValue(template, foreign);

        // Someone recovering for real should not be blocked by one bad share when the other
        // two are sufficient.
        var result = CliRunner.Run("combine", "--ignore-invalid-shares", good[0], good[1], forged);

        Assert.Equal(Program.ExitSuccess, result.ExitCode);
        Assert.Contains(Secret, result.StdOut, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("do not agree", result.StdOut, StringComparison.Ordinal);
        Assert.Contains("--ignore-invalid-shares", result.StdOut, StringComparison.Ordinal);
    }

    [Fact]
    public void Combine_IgnoreInvalidShares_WorksWhenTheBadShareIsFirst()
    {
        var good = ExtractMnemonics(
            CliRunner.Run("split", "--secret", Secret, "--threshold", "2", "--shares", "3").StdOut);
        var other = ExtractMnemonics(
            CliRunner.Run("split", "--secret", "ffeeddccbbaa99887766554433221100", "--threshold", "2", "--shares", "3").StdOut);

        var template = Slip39ShareParser.ParseFromMnemonic(good[0]);
        var foreign = Slip39ShareParser.ParseFromMnemonic(other[0]).ShareValue;
        string forged = ForgeShareWithForeignValue(template, foreign);

        // Position must not matter: identifying the bad share relies on searching for a
        // subset that passes the digest check, not on assuming the first ones are sound.
        var result = CliRunner.Run("combine", "--ignore-invalid-shares", forged, good[1], good[2]);

        Assert.Equal(Program.ExitSuccess, result.ExitCode);
        Assert.Contains(Secret, result.StdOut, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Combine_DefaultRefusal_PointsAtTheFlag()
    {
        var good = ExtractMnemonics(
            CliRunner.Run("split", "--secret", Secret, "--threshold", "2", "--shares", "3").StdOut);
        var other = ExtractMnemonics(
            CliRunner.Run("split", "--secret", "ffeeddccbbaa99887766554433221100", "--threshold", "2", "--shares", "3").StdOut);

        var template = Slip39ShareParser.ParseFromMnemonic(good[2]);
        var foreign = Slip39ShareParser.ParseFromMnemonic(other[2]).ShareValue;
        string forged = ForgeShareWithForeignValue(template, foreign);

        var result = CliRunner.Run("combine", good[0], good[1], forged);

        Assert.Equal(Program.ExitFailure, result.ExitCode);
        Assert.Contains("--ignore-invalid-shares", result.StdErr, StringComparison.Ordinal);
    }

    /// <summary>A share whose value has been altered, so it lies on no shared polynomial.</summary>
    static string ForgeDamagedShare(Slip39Share template, byte marker)
    {
        var damaged = (byte[])template.ShareValue.Clone();
        damaged[0] ^= marker;
        return ForgeShareWithForeignValue(template, damaged);
    }

    [Fact]
    public void Combine_IgnoreInvalidShares_StillFailsWhenNoQuorumSurvives()
    {
        var good = ExtractMnemonics(
            CliRunner.Run("split", "--secret", Secret, "--threshold", "3", "--shares", "5").StdOut);

        // Damage three of five in a 3-of-5: only two sound shares remain, one short.
        var forged = new List<string>();
        for (int i = 2; i < 5; i++)
        {
            forged.Add(ForgeDamagedShare(Slip39ShareParser.ParseFromMnemonic(good[i]), (byte)(i + 1)));
        }

        var args = new[] { "combine", "--ignore-invalid-shares", good[0], good[1] }.Concat(forged).ToArray();
        var result = CliRunner.Run(args);

        Assert.Equal(Program.ExitFailure, result.ExitCode);
        Assert.DoesNotContain(Secret, result.Combined, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Combine_SharesDescribingTwoDifferentSecrets_RecoversNeither()
    {
        const string OtherSecret = "ffeeddccbbaa99887766554433221100";

        var good = ExtractMnemonics(
            CliRunner.Run("split", "--secret", Secret, "--threshold", "2", "--shares", "3").StdOut);
        var other = ExtractMnemonics(
            CliRunner.Run("split", "--secret", OtherSecret, "--threshold", "2", "--shares", "5").StdOut);

        // Two shares of one backup and two of another, relabelled to look like one set. The
        // foreign shares keep their own member indices, so they remain genuine points on the
        // other backup's polynomial: each pair reconstructs a secret, and they are different
        // secrets. Choosing either would mean silently returning a secret nobody asked for.
        var header = Slip39ShareParser.ParseFromMnemonic(good[0]);
        var mixed = new List<string> { good[0], good[1] };

        foreach (int i in new[] { 3, 4 })
        {
            var foreign = Slip39ShareParser.ParseFromMnemonic(other[i]);
            var relabelled = new Slip39Share(
                header.Identifier, header.IsExtendable, header.IterationExponent,
                header.GroupIndex, header.GroupThreshold, header.GroupCount,
                foreign.MemberIndex, header.MemberThreshold, foreign.ShareValue, 0);

            mixed.Add(ForgeShareWithForeignValue(relabelled, foreign.ShareValue));
        }

        var args = new[] { "combine", "--ignore-invalid-shares" }.Concat(mixed).ToArray();
        var result = CliRunner.Run(args);

        Assert.Equal(Program.ExitFailure, result.ExitCode);
        Assert.DoesNotContain(Secret, result.Combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(OtherSecret, result.Combined, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_SharesThatAgree_SaysSo()
    {
        var mnemonics = ExtractMnemonics(
            CliRunner.Run("split", "--secret", Secret, "--threshold", "2", "--shares", "3").StdOut);

        var result = CliRunner.Run("validate", mnemonics[0], mnemonics[1], mnemonics[2]);

        Assert.Equal(Program.ExitSuccess, result.ExitCode);
        Assert.Contains("agree with each other", result.StdOut, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_SharesThatContradictEachOther_Fails()
    {
        var good = ExtractMnemonics(
            CliRunner.Run("split", "--secret", Secret, "--threshold", "2", "--shares", "3").StdOut);
        var other = ExtractMnemonics(
            CliRunner.Run("split", "--secret", "ffeeddccbbaa99887766554433221100", "--threshold", "2", "--shares", "3").StdOut);

        var template = Slip39ShareParser.ParseFromMnemonic(good[2]);
        var foreign = Slip39ShareParser.ParseFromMnemonic(other[2]).ShareValue;
        string forged = ForgeShareWithForeignValue(template, foreign);

        // Every share passes its own checksum, so the old per-share validation said VALID.
        var result = CliRunner.Run("validate", good[0], good[1], forged);

        Assert.Contains("✓ VALID", result.StdOut, StringComparison.Ordinal);
        Assert.Equal(Program.ExitFailure, result.ExitCode);
        Assert.Contains("contradict each other", result.StdErr, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_TooFewSharesToCrossCheck_SucceedsButSaysNothingWasConfirmed()
    {
        var mnemonics = ExtractMnemonics(
            CliRunner.Run("split", "--secret", Secret, "--threshold", "3", "--shares", "5").StdOut);

        var result = CliRunner.Run("validate", mnemonics[0], mnemonics[1]);

        Assert.Equal(Program.ExitSuccess, result.ExitCode);
        Assert.Contains("nothing confirms they belong together", result.StdOut, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ validate

    [Fact]
    public void Validate_GoodShares_Succeeds()
    {
        var mnemonics = ExtractMnemonics(
            CliRunner.Run("split", "--secret", Secret, "--threshold", "2", "--shares", "3").StdOut);

        var result = CliRunner.Run("validate", mnemonics[0], mnemonics[1], mnemonics[2]);

        Assert.Equal(Program.ExitSuccess, result.ExitCode);
    }

    [Fact]
    public void Validate_CorruptShare_Fails()
    {
        var mnemonic = ExtractMnemonics(
            CliRunner.Run("split", "--secret", Secret, "--threshold", "1", "--shares", "1").StdOut)[0];

        // Swap one word for another valid wordlist entry: the checksum must catch it.
        var words = mnemonic.Split(' ');
        words[^1] = words[^1] == "academic" ? "acid" : "academic";

        var result = CliRunner.Run("validate", string.Join(' ', words));

        Assert.Equal(Program.ExitFailure, result.ExitCode);
    }
}
