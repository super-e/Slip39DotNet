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
