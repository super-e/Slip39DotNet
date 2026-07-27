using Slip39.Core;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SystemConsole = System.Console;

namespace Slip39.Console;

class Program
{
    /// <summary>Process exit code signalling that the command completed successfully.</summary>
    internal const int ExitSuccess = 0;

    /// <summary>Process exit code signalling that the command failed.</summary>
    internal const int ExitFailure = 1;

    static int Main(string[] args) => Run(args);

    /// <summary>
    /// Runs a single CLI invocation and returns the process exit code.
    /// </summary>
    /// <remarks>
    /// Kept separate from <c>Main</c> so tests can drive the CLI in-process and observe the
    /// exit code. Nothing here calls <see cref="Environment.Exit"/>: every command reports
    /// success or failure through its return value, so a failing command is detectable by a
    /// script (and by a test) rather than only by reading the message it printed.
    /// </remarks>
    internal static int Run(string[] args)
    {
        // If no arguments provided, show help
        if (args.Length == 0)
        {
            ShowHelp();
            return ExitSuccess;
        }

        string command = args[0].ToLowerInvariant();

        try
        {
            switch (command)
            {
                case "split":
                    return HandleSplitCommand(args[1..]);
                case "combine":
                    return HandleCombineCommand(args[1..]);
                case "info":
                    return HandleInfoCommand(args[1..]);
                case "validate":
                    return HandleValidateCommand(args[1..]);
                case "generate":
                    return HandleGenerateCommand(args[1..]);
                case "split-xpriv":
                    return HandleSplitXprivCommand(args[1..]);
                case "help":
                    ShowHelp();
                    return ExitSuccess;
                default:
                    SystemConsole.Error.WriteLine($"Unknown command: {command}");
                    SystemConsole.Error.WriteLine("Use 'help' to see available commands.");
                    return ExitFailure;
            }
        }
        catch (Exception ex)
        {
            SystemConsole.Error.WriteLine($"Error: {ex.Message}");
            return ExitFailure;
        }
    }

    /// <summary>
    /// Reports an unrecognised option and fails the command.
    /// </summary>
    /// <remarks>
    /// Unknown options used to fall through the argument-parsing switch untouched, so
    /// <c>--treshold 5</c> silently left the threshold at its default: the user asked for
    /// 5-of-7 and got 2-of-7 with no indication anything had been ignored. A typo must never
    /// quietly weaken the sharing parameters.
    /// </remarks>
    static int UnknownOption(string option, string command)
    {
        SystemConsole.Error.WriteLine($"Error: unknown option '{option}' for command '{command}'");
        SystemConsole.Error.WriteLine($"Use 'slip39 {command} --help' to see the available options.");
        return ExitFailure;
    }

    static void ShowHelp()
    {
        SystemConsole.WriteLine("SLIP-0039 Shamir's Secret Sharing Tool");
        SystemConsole.WriteLine("=====================================\n");
        
        SystemConsole.WriteLine("Available Commands:");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("  split      - Split a secret into SLIP-0039 shares");
        SystemConsole.WriteLine("  split-xpriv- Split a BIP32 extended private key into SLIP-0039 shares");
        SystemConsole.WriteLine("  combine    - Combine SLIP-0039 shares to recover secret");
        SystemConsole.WriteLine("  info       - Display detailed information about a share");
        SystemConsole.WriteLine("  validate   - Validate SLIP-0039 share checksums");
        SystemConsole.WriteLine("  generate   - Generate a random secret and split it");
        SystemConsole.WriteLine("  help       - Show this help message");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("Examples:");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("  # Split a hex secret into 3 shares, requiring 2 to recover:");
        SystemConsole.WriteLine("  slip39 split --secret 458d0765afec7bb0fb45a50a84d5bf74d75a2b1e69fd79015ce2bb23a9ce9ef3 --threshold 2 --shares 3");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("  # Combine shares to recover the original secret:");
        SystemConsole.WriteLine("  slip39 combine --shares \"share1\" \"share2\"");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("  # Show detailed information about a share:");
        SystemConsole.WriteLine("  slip39 info \"mild isolate academic acid apart...\"");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("  # Validate share checksums:");
        SystemConsole.WriteLine("  slip39 validate \"share1\" \"share2\" \"share3\"");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("  # Generate and split a new 256-bit secret:");
        SystemConsole.WriteLine("  slip39 generate --bits 256 --threshold 2 --shares 3");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("  # Split an existing BIP32 extended private key:");
        SystemConsole.WriteLine("  slip39 split-xpriv --xpriv xprv9s21ZrQH... --threshold 2 --shares 3");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("Use 'slip39 [command] --help' for detailed command options.");
    }

    static int HandleSplitCommand(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help"))
        {
            ShowSplitHelp();
            return ExitSuccess;
        }

        string? secretHex = null;
        int threshold = 2;
        int shares = 3;
        int groupThreshold = 1;
        var groupConfigs = new List<string>();
        string? passphrase = null;
        byte iterationExponent = 0;
        bool extendable = false;
        string outputFormat = "text";

        // Parse arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--secret":
                    secretHex = GetNextArgument(args, ref i, "--secret");
                    break;
                case "--threshold":
                    threshold = ParseIntArgument(args, ref i, "--threshold");
                    break;
                case "--shares":
                    shares = ParseIntArgument(args, ref i, "--shares");
                    break;
                case "--group-threshold":
                    groupThreshold = ParseIntArgument(args, ref i, "--group-threshold");
                    break;
                case "--groups":
                    groupConfigs.Add(GetNextArgument(args, ref i, "--groups"));
                    break;
                case "--passphrase":
                    passphrase = GetNextArgument(args, ref i, "--passphrase");
                    break;
                case "--iterations":
                    iterationExponent = ParseByteArgument(args, ref i, "--iterations");
                    break;
                case "--extendable":
                    extendable = true;
                    break;
                case "--format":
                    outputFormat = GetNextArgument(args, ref i, "--format");
                    break;
                default:
                    return UnknownOption(args[i], "split");
            }
        }

        if (string.IsNullOrEmpty(secretHex))
        {
            SystemConsole.Error.WriteLine("Error: --secret is required");
            return ExitFailure;
        }

        byte[]? secret = null;
        try
        {
            secret = Convert.FromHexString(secretHex);

            List<Slip39ShareGeneration.GroupConfig> parsedGroupConfigs;

            // If groups are specified, use multi-group configuration
            if (groupConfigs.Count > 0)
            {
                parsedGroupConfigs = ParseGroupConfigurations(groupConfigs);

                // Validate group threshold
                if (groupThreshold > parsedGroupConfigs.Count)
                {
                    SystemConsole.Error.WriteLine($"Error: Group threshold ({groupThreshold}) cannot exceed number of groups ({parsedGroupConfigs.Count})");
                    return ExitFailure;
                }
            }
            else
            {
                // Single group configuration (backward compatibility)
                parsedGroupConfigs = new List<Slip39ShareGeneration.GroupConfig>
                {
                    new(threshold, shares)
                };
                groupThreshold = 1;
            }

            var generatedShares = Slip39ShareGeneration.GenerateShares(
                groupThreshold: groupThreshold,
                groupConfigs: parsedGroupConfigs,
                masterSecret: secret,
                passphrase: passphrase,
                iterationExponent: iterationExponent,
                isExtendable: extendable
            );

            // Display configuration summary
            SystemConsole.WriteLine($"Successfully generated {generatedShares.Count} shares:");
            
            if (parsedGroupConfigs.Count == 1)
            {
                SystemConsole.WriteLine($"Single Group: {threshold} of {shares} shares required to recover");
            }
            else
            {
                SystemConsole.WriteLine($"Multi-Group Configuration: {groupThreshold} groups required out of {parsedGroupConfigs.Count} total groups");
                for (int i = 0; i < parsedGroupConfigs.Count; i++)
                {
                    var config = parsedGroupConfigs[i];
                    SystemConsole.WriteLine($"  Group {i + 1}: {config.MemberThreshold} of {config.MemberCount} shares");
                }
            }
            
            SystemConsole.WriteLine($"Passphrase: {FormatPassphraseDisplay(passphrase)}");
            SystemConsole.WriteLine();

            DisplayGeneratedShares(generatedShares, outputFormat);
            return ExitSuccess;
        }
        catch (Exception ex)
        {
            SystemConsole.Error.WriteLine($"Error splitting secret: {ex.Message}");
            return ExitFailure;
        }
        finally
        {
            // The secret was handed to us on the command line and lives on in the shell's
            // history either way, but there is no reason to leave a second copy sitting in
            // this process's heap once the shares have been produced.
            if (secret != null) CryptographicOperations.ZeroMemory(secret);
        }
    }

    static List<Slip39ShareGeneration.GroupConfig> ParseGroupConfigurations(List<string> groupConfigs)
    {
        var configs = new List<Slip39ShareGeneration.GroupConfig>();
        
        foreach (var configStr in groupConfigs)
        {
            // Parse individual group configurations separated by commas
            var groups = configStr.Split(',', StringSplitOptions.RemoveEmptyEntries);
            
            foreach (var group in groups)
            {
                // Parse format like "2-of-3" or "2/3"
                var parts = group.Trim().Split(new[] { "-of-", "/", ":", " of " }, StringSplitOptions.RemoveEmptyEntries);
                
                if (parts.Length != 2)
                {
                    throw new ArgumentException($"Invalid group configuration format: '{group}'. Expected format: 'threshold-of-total' (e.g., '2-of-3')");
                }
                
                if (!int.TryParse(parts[0].Trim(), out int memberThreshold) || !int.TryParse(parts[1].Trim(), out int memberCount))
                {
                    throw new ArgumentException($"Invalid numbers in group configuration: '{group}'");
                }
                
                if (memberThreshold <= 0 || memberCount <= 0 || memberThreshold > memberCount)
                {
                    throw new ArgumentException($"Invalid group configuration: '{group}'. Threshold must be positive and not exceed total count.");
                }
                
                configs.Add(new Slip39ShareGeneration.GroupConfig(memberThreshold, memberCount));
            }
        }
        
        if (configs.Count == 0)
        {
            throw new ArgumentException("No valid group configurations found");
        }
        
        return configs;
    }

    static void ShowSplitHelp()
    {
        SystemConsole.WriteLine("Split Command - Split a secret into SLIP-0039 shares");
        SystemConsole.WriteLine("==================================================\n");
        
        SystemConsole.WriteLine("Usage:");
        SystemConsole.WriteLine("  slip39 split --secret <hex> [options]\n");
        
        SystemConsole.WriteLine("Required Arguments:");
        SystemConsole.WriteLine("  --secret <hex>     Hexadecimal secret to split (32 or 64 hex chars for 128/256-bit)\n");
        
        SystemConsole.WriteLine("Single Group Mode (Simple):");
        SystemConsole.WriteLine("  --threshold <n>    Number of shares needed to recover (default: 2)");
        SystemConsole.WriteLine("  --shares <n>       Total number of shares to generate (default: 3)\n");
        
        SystemConsole.WriteLine("Multi-Group Mode (Advanced):");
        SystemConsole.WriteLine("  --group-threshold <n>  Number of groups needed to recover (default: 1)");
        SystemConsole.WriteLine("  --groups <config>      Group configurations in format 'threshold-of-total'");
        SystemConsole.WriteLine("                         Examples: \"2-of-3\" or \"2-of-3,3-of-5,1-of-1\"\n");
        
        SystemConsole.WriteLine("Common Options:");
        SystemConsole.WriteLine("  --passphrase <p>   Custom passphrase (default: TREZOR)");
        SystemConsole.WriteLine("  --iterations <n>   Iteration exponent 0-15 (default: 0 = 10,000 iterations)");
        SystemConsole.WriteLine("  --extendable       Generate extendable shares");
        SystemConsole.WriteLine("  --format <fmt>     Output format: text, json, hex (default: text)\n");
        
        SystemConsole.WriteLine("Examples:");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # Simple single group (2-of-3):");
        SystemConsole.WriteLine("  slip39 split --secret 458d0765afec7bb0fb45a50a84d5bf74d75a2b1e69fd79015ce2bb23a9ce9ef3 --threshold 2 --shares 3");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # Multi-group configuration requiring 2 groups:");
        SystemConsole.WriteLine("  slip39 split --secret 1234abcd --group-threshold 2 --groups \"2-of-3,3-of-5,1-of-1\"");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # Advanced: Company backup (2 groups needed: 3-of-5 directors OR 2-of-3 executives):");
        SystemConsole.WriteLine("  slip39 split --secret 1234abcd --group-threshold 1 --groups \"3-of-5,2-of-3\"");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # Bank-style security (3 groups needed: IT + Legal + Management):");
        SystemConsole.WriteLine("  slip39 split --secret 1234abcd --group-threshold 3 --groups \"2-of-3,1-of-2,2-of-4\"");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # With custom passphrase and JSON output:");
        SystemConsole.WriteLine("  slip39 split --secret 1234abcd --groups \"2-of-3\" --passphrase mypass --format json");
    }

    static int HandleCombineCommand(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help"))
        {
            ShowCombineHelp();
            return ExitSuccess;
        }

        var shareStrings = new List<string>();
        string? passphrase = null;
        string outputFormat = "hex";
        bool showBip32 = false;
        bool ignoreInvalidShares = false;

        // Parse arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--shares":
                    // Collect all following arguments until next flag or end
                    i++;
                    while (i < args.Length && !args[i].StartsWith("--"))
                    {
                        shareStrings.Add(args[i]);
                        i++;
                    }
                    i--; // Back up one since the loop will increment
                    break;
                case "--passphrase":
                    passphrase = GetNextArgument(args, ref i, "--passphrase");
                    break;
                case "--format":
                    outputFormat = GetNextArgument(args, ref i, "--format");
                    break;
                case "--bip32":
                    showBip32 = true;
                    break;
                case "--ignore-invalid-shares":
                    ignoreInvalidShares = true;
                    break;
                default:
                    // If it doesn't start with --, treat as a share
                    if (!args[i].StartsWith("--"))
                    {
                        shareStrings.Add(args[i]);
                        break;
                    }
                    return UnknownOption(args[i], "combine");
            }
        }

        if (shareStrings.Count == 0)
        {
            SystemConsole.Error.WriteLine("Error: At least one share is required");
            return ExitFailure;
        }

        byte[]? masterSecret = null;
        try
        {
            var shares = new List<Slip39Share>();

            foreach (var shareString in shareStrings)
            {
                var share = Slip39ShareParser.ParseFromMnemonic(shareString);
                shares.Add(share);
            }

            // The library requires exactly the member threshold per group, as SLIP-0039 does.
            // Handing it every share you own is a natural thing to want to do, though, so the
            // CLI accepts a surplus and puts it to use: each extra share is checked against
            // the others before the set is trimmed for recovery. That turns shares that were
            // previously discarded unread into the one thing that can tell you a backup has
            // rotted.
            var used = SelectSharesForRecovery(shares, ignoreInvalidShares);
            if (used == null)
                return ExitFailure;

            masterSecret = Slip39ShareCombination.CombineShares(used, passphrase);

            SystemConsole.WriteLine("Successfully recovered master secret!");
            SystemConsole.WriteLine();
            
            // Say both numbers when they differ: recovery consumes exactly the threshold, and
            // claiming to have "used" shares that only took part in the cross-check would
            // overstate what the run proves about them.
            SystemConsole.WriteLine(used.Count == shares.Count
                ? $"Shares used: {used.Count}"
                : $"Shares used: {used.Count} of the {shares.Count} supplied (the rest were cross-checked)");
            SystemConsole.WriteLine($"Passphrase: {FormatPassphraseDisplay(passphrase)}");
            SystemConsole.WriteLine();

            switch (outputFormat.ToLowerInvariant())
            {
                case "base64":
                    SystemConsole.WriteLine($"Master Secret (Base64): {Convert.ToBase64String(masterSecret)}");
                    break;
                case "binary":
                    SystemConsole.WriteLine($"Master Secret (Binary): {string.Join("", masterSecret.Select(b => Convert.ToString(b, 2).PadLeft(8, '0')))}");
                    break;
                default:
                    SystemConsole.WriteLine($"Master Secret (Hex): {Convert.ToHexString(masterSecret).ToLowerInvariant()}");
                    break;
            }

            if (showBip32)
            {
                try
                {
                    // Check if this is a 64-byte secret from split-xpriv (private key + chain code)
                    if (masterSecret.Length == 64)
                    {
                        // Reconstruct the original BIP32 extended private key
                        string reconstructedXpriv = Bip32MasterKey.ReconstructFromComponents(masterSecret);
                        SystemConsole.WriteLine($"Reconstructed BIP32 Extended Private Key: {reconstructedXpriv}");
                    }
                    else
                    {
                        // Generate a new BIP32 master key from the secret
                        string bip32Key = Bip32MasterKey.GenerateMasterKey(masterSecret);
                        SystemConsole.WriteLine($"BIP32 Master Key: {bip32Key}");
                    }
                }
                catch (Exception ex)
                {
                    SystemConsole.Error.WriteLine($"Warning: Could not generate BIP32 key: {ex.Message}");
                }
            }

            return ExitSuccess;
        }
        catch (Exception ex)
        {
            SystemConsole.Error.WriteLine($"Error combining shares: {ex.Message}");
            return ExitFailure;
        }
        finally
        {
            // CombineShares hands ownership of the master secret to its caller — that is us.
            // The library documents that the caller should clear it; being the library's own
            // reference consumer, this is exactly where that has to be demonstrated.
            if (masterSecret != null) CryptographicOperations.ZeroMemory(masterSecret);
        }
    }

    /// <summary>
    /// Decides which shares to recover from, cross-checking any surplus first.
    /// </summary>
    /// <param name="shares">Every share the user supplied.</param>
    /// <param name="ignoreInvalid">
    /// When true, shares found to disagree are dropped and recovery proceeds from the rest,
    /// provided a quorum survives in every group.
    /// </param>
    /// <returns>The shares to combine, or null when a report has been printed and the command should fail.</returns>
    /// <remarks>
    /// Someone running this command may be recovering under pressure, and a single share that
    /// was mis-transcribed years ago should not stand between them and their secret when the
    /// remaining shares are sufficient. It should not pass unmentioned either — a degraded
    /// backup is worth knowing about — so the default reports it and stops, and
    /// --ignore-invalid-shares carries on without it.
    /// </remarks>
    static List<Slip39Share>? SelectSharesForRecovery(List<Slip39Share> shares, bool ignoreInvalid)
    {
        bool hasSurplus = shares
            .GroupBy(s => s.GroupIndex)
            .Any(g => g.Count() > g.First().ActualMemberThreshold);

        // With no surplus there is nothing extra to check: every share is needed, and
        // CombineShares applies the SLIP-0039 digest check to exactly this set anyway.
        if (!hasSurplus)
            return shares;

        var report = Slip39ShareCombination.VerifyShares(shares);

        SystemConsole.WriteLine($"Checked all {shares.Count} shares against each other.");

        if (report.AllConsistent)
        {
            SystemConsole.WriteLine("✓ Every share agrees with the others in its group.");
            SystemConsole.WriteLine();
            return TrimToThresholds(shares);
        }

        var bad = report.Inconsistent.ToList();
        var stream = ignoreInvalid ? SystemConsole.Out : SystemConsole.Error;

        stream.WriteLine($"{(ignoreInvalid ? "⚠" : "✗")} {bad.Count} share(s) do not agree with the others in their group:");
        foreach (var entry in bad)
        {
            stream.WriteLine($"    group {entry.Share.GroupIndex}, member {entry.Share.MemberIndex}: {entry.Detail}");
        }
        stream.WriteLine();

        if (!ignoreInvalid)
        {
            SystemConsole.Error.WriteLine("Refusing to recover from a set that contradicts itself.");
            SystemConsole.Error.WriteLine("Re-check the transcription of the shares listed above. If you are confident");
            SystemConsole.Error.WriteLine("in the remaining shares, re-run with --ignore-invalid-shares to recover from");
            SystemConsole.Error.WriteLine("those alone — the recovered secret is still verified against its digest.");
            return null;
        }

        var badShares = bad.Select(b => b.Share).ToHashSet();
        var usable = shares.Where(s => !badShares.Contains(s)).ToList();

        // Dropping shares can take a group below its threshold, or remove it entirely.
        foreach (var group in shares.GroupBy(s => s.GroupIndex).OrderBy(g => g.Key))
        {
            int threshold = group.First().ActualMemberThreshold;
            int surviving = usable.Count(s => s.GroupIndex == group.Key);

            if (surviving < threshold)
            {
                SystemConsole.Error.WriteLine(
                    $"Error: group {group.Key} has only {surviving} usable share(s) left but needs {threshold}.");
                SystemConsole.Error.WriteLine("Not enough sound shares remain to recover the secret.");
                return null;
            }
        }

        SystemConsole.WriteLine("Continuing without them, as requested by --ignore-invalid-shares.");
        SystemConsole.WriteLine();
        return TrimToThresholds(usable);
    }

    /// <summary>
    /// Keeps exactly the member threshold from each group, which is what the library accepts.
    /// </summary>
    static List<Slip39Share> TrimToThresholds(List<Slip39Share> shares) =>
        shares.GroupBy(s => s.GroupIndex)
              .SelectMany(g => g.Take(g.First().ActualMemberThreshold))
              .ToList();

    static void ShowCombineHelp()
    {
        SystemConsole.WriteLine("Combine Command - Combine SLIP-0039 shares to recover secret");
        SystemConsole.WriteLine("==========================================================\n");
        
        SystemConsole.WriteLine("Usage:");
        SystemConsole.WriteLine("  slip39 combine [options] \"share1\" \"share2\" [\"share3\" ...]\n");
        
        SystemConsole.WriteLine("Optional Arguments:");
        SystemConsole.WriteLine("  --shares \"s1\" \"s2\"  List of mnemonic shares to combine");
        SystemConsole.WriteLine("  --passphrase <p>    Custom passphrase (default: TREZOR)");
        SystemConsole.WriteLine("  --format <fmt>      Output format: hex, base64, binary (default: hex)");
        SystemConsole.WriteLine("  --bip32             Also show BIP32 master key");
        SystemConsole.WriteLine("  --ignore-invalid-shares");
        SystemConsole.WriteLine("                      Recover from the sound shares even if some disagree\n");

        SystemConsole.WriteLine("Passing more shares than the threshold is allowed: the extra ones are checked");
        SystemConsole.WriteLine("against the rest. By default recovery stops if any of them disagrees, so a");
        SystemConsole.WriteLine("backup that has degraded does not pass unnoticed. Use --ignore-invalid-shares");
        SystemConsole.WriteLine("to recover anyway from the shares that do agree, as long as a quorum remains;");
        SystemConsole.WriteLine("the recovered secret is verified against its SLIP-0039 digest either way.\n");

        SystemConsole.WriteLine("Examples:");
        SystemConsole.WriteLine("  slip39 combine \"mild isolate academic acid...\" \"mild isolate academic agency...\"");
        SystemConsole.WriteLine("  slip39 combine --passphrase mypass --bip32 \"share1\" \"share2\"");
        SystemConsole.WriteLine("  slip39 combine --format base64 \"share1\" \"share2\"");
    }

    static int HandleInfoCommand(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help"))
        {
            ShowInfoHelp();
            return ExitSuccess;
        }

        string? shareString = null;
        string outputFormat = "text";
        bool validateChecksum = true;

        // Scan every argument rather than assuming the mnemonic is args[0]: the documented
        // usage puts the options first ("slip39 info --format json <share>"), which used to
        // take "--format" itself as the mnemonic and fail with a word-count error.
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--format":
                    outputFormat = GetNextArgument(args, ref i, "--format");
                    break;
                case "--no-validate":
                    validateChecksum = false;
                    break;
                default:
                    if (args[i].StartsWith("--"))
                        return UnknownOption(args[i], "info");
                    if (shareString != null)
                    {
                        SystemConsole.Error.WriteLine("Error: 'info' accepts a single share; quote the mnemonic so the shell passes it as one argument.");
                        return ExitFailure;
                    }
                    shareString = args[i];
                    break;
            }
        }

        if (shareString == null)
        {
            SystemConsole.Error.WriteLine("Error: a share mnemonic is required");
            return ExitFailure;
        }

        try
        {
            var share = Slip39ShareParser.ParseFromMnemonic(shareString);
            
            bool checksumValid = true;
            if (validateChecksum)
            {
                try
                {
                    Slip39ShareCombination.ValidateChecksums(new List<Slip39Share> { share });
                    SystemConsole.WriteLine("✓ Checksum validation: PASSED\n");
                }
                catch
                {
                    checksumValid = false;
                    SystemConsole.WriteLine("✗ Checksum validation: FAILED\n");
                }
            }

            switch (outputFormat.ToLowerInvariant())
            {
                case "json":
                    SystemConsole.WriteLine(Slip39ShareParser.ToJson(share, true));
                    break;
                    
                case "hex":
                    SystemConsole.WriteLine($"Hex representation: {share.ToHex()}");
                    break;
                    
                default:
                    ShowShareInfoText(share);
                    break;
            }

            return checksumValid ? ExitSuccess : ExitFailure;
        }
        catch (Exception ex)
        {
            SystemConsole.Error.WriteLine($"Error parsing share: {ex.Message}");
            return ExitFailure;
        }
    }

    static void ShowShareInfoText(Slip39Share share)
    {
        SystemConsole.WriteLine("SLIP-0039 Share Information");
        SystemConsole.WriteLine("==========================\n");
        
        SystemConsole.WriteLine($"Identifier: {share.Identifier} (0x{share.Identifier:X4})");
        SystemConsole.WriteLine($"Extendable: {(share.IsExtendable ? "Yes" : "No")}");
        SystemConsole.WriteLine($"Iteration Exponent: {share.IterationExponent}");
        SystemConsole.WriteLine($"Total Iterations: {share.TotalIterations:N0}");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("Group Configuration:");
        SystemConsole.WriteLine($"  Group Index: {share.GroupIndex}");
        SystemConsole.WriteLine($"  Group Threshold: {share.ActualGroupThreshold} (need {share.ActualGroupThreshold} groups)");
        SystemConsole.WriteLine($"  Group Count: {share.ActualGroupCount} (total {share.ActualGroupCount} groups)");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("Member Configuration:");
        SystemConsole.WriteLine($"  Member Index: {share.MemberIndex}");
        SystemConsole.WriteLine($"  Member Threshold: {share.ActualMemberThreshold} (need {share.ActualMemberThreshold} shares from this group)");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("Share Data:");
        SystemConsole.WriteLine($"  Share Value Length: {share.ShareValue.Length} bytes ({share.ShareValue.Length * 8} bits)");
        SystemConsole.WriteLine($"  Share Value: {Convert.ToHexString(share.ShareValue).ToLowerInvariant()}");
        SystemConsole.WriteLine($"  Checksum: {share.Checksum} (0x{share.Checksum:X8})");
        SystemConsole.WriteLine($"  Checksum Type: {share.ChecksumCustomizationString}");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("Recovery Requirements:");
        if (share.ActualGroupCount == 1)
        {
            SystemConsole.WriteLine($"  • Need {share.ActualMemberThreshold} shares from this single group");
        }
        else
        {
            SystemConsole.WriteLine($"  • Need {share.ActualGroupThreshold} groups out of {share.ActualGroupCount} total groups");
            SystemConsole.WriteLine($"  • Need {share.ActualMemberThreshold} shares from each required group");
        }
        
        int estimatedSecretBits = share.ShareValue.Length * 8;
        if (estimatedSecretBits >= 128 && estimatedSecretBits <= 160)
            SystemConsole.WriteLine("  • Estimated original secret size: 128 bits (16 bytes)");
        else if (estimatedSecretBits >= 256 && estimatedSecretBits <= 280)
            SystemConsole.WriteLine("  • Estimated original secret size: 256 bits (32 bytes)");
        else
            SystemConsole.WriteLine($"  • Estimated original secret size: {estimatedSecretBits} bits ({estimatedSecretBits / 8} bytes)");
    }

    static void ShowInfoHelp()
    {
        SystemConsole.WriteLine("Info Command - Display detailed information about a share");
        SystemConsole.WriteLine("========================================================\n");
        
        SystemConsole.WriteLine("Usage:");
        SystemConsole.WriteLine("  slip39 info [options] \"share mnemonic\"\n");
        
        SystemConsole.WriteLine("Optional Arguments:");
        SystemConsole.WriteLine("  --format <fmt>    Output format: text, json, hex (default: text)");
        SystemConsole.WriteLine("  --no-validate     Skip checksum validation\n");
        
        SystemConsole.WriteLine("Examples:");
        SystemConsole.WriteLine("  slip39 info \"mild isolate academic acid apart...\"");
        SystemConsole.WriteLine("  slip39 info --format json \"share mnemonic\"");
        SystemConsole.WriteLine("  slip39 info --no-validate \"potentially invalid share\"");
    }

    static int HandleValidateCommand(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help"))
        {
            ShowValidateHelp();
            return ExitSuccess;
        }

        var shareStrings = new List<string>();
        bool verbose = false;

        // Parse arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--verbose":
                    verbose = true;
                    break;
                default:
                    if (!args[i].StartsWith("--"))
                    {
                        shareStrings.Add(args[i]);
                        break;
                    }
                    return UnknownOption(args[i], "validate");
            }
        }

        if (shareStrings.Count == 0)
        {
            SystemConsole.Error.WriteLine("Error: At least one share is required");
            return ExitFailure;
        }

        int validCount = 0;
        int totalCount = shareStrings.Count;
        var parsedShares = new List<Slip39Share>();

        SystemConsole.WriteLine($"Validating {totalCount} shares...\n");

        for (int i = 0; i < shareStrings.Count; i++)
        {
            try
            {
                var share = Slip39ShareParser.ParseFromMnemonic(shareStrings[i]);
                
                try
                {
                    Slip39ShareCombination.ValidateChecksums(new List<Slip39Share> { share });
                    SystemConsole.WriteLine($"Share {i + 1}: ✓ VALID");
                    validCount++;
                    parsedShares.Add(share);
                    
                    if (verbose)
                    {
                        SystemConsole.WriteLine($"  Identifier: {share.Identifier}");
                        SystemConsole.WriteLine($"  Group: {share.GroupIndex}, Member: {share.MemberIndex}");
                        SystemConsole.WriteLine($"  Checksum: 0x{share.Checksum:X8}\n");
                    }
                }
                catch (Exception ex)
                {
                    SystemConsole.WriteLine($"Share {i + 1}: ✗ INVALID CHECKSUM - {ex.Message}");
                    if (verbose)
                    {
                        SystemConsole.WriteLine($"  Parsed successfully but checksum failed");
                        SystemConsole.WriteLine($"  Identifier: {share.Identifier}");
                        SystemConsole.WriteLine($"  Checksum: 0x{share.Checksum:X8}\n");
                    }
                }
            }
            catch (Exception ex)
            {
                SystemConsole.WriteLine($"Share {i + 1}: ✗ PARSE ERROR - {ex.Message}");
                if (verbose)
                {
                    SystemConsole.WriteLine($"  Could not parse share mnemonic\n");
                }
            }
        }

        SystemConsole.WriteLine($"\nValidation Summary: {validCount}/{totalCount} shares valid");
        
        if (validCount != totalCount)
        {
            SystemConsole.WriteLine("⚠ Some shares have validation issues");
            return ExitFailure;
        }

        SystemConsole.WriteLine("✓ All shares are individually valid.");

        // A per-share checksum only proves each mnemonic was transcribed without a typo. It
        // says nothing about whether the shares belong together and still reconstruct the
        // same secret — which is the question someone checking an old backup is actually
        // asking. Cross-check them whenever there is more than one.
        if (parsedShares.Count < 2)
            return ExitSuccess;

        SystemConsole.WriteLine();
        try
        {
            var report = Slip39ShareCombination.VerifyShares(parsedShares);

            if (!report.AllConsistent)
            {
                SystemConsole.Error.WriteLine("✗ These shares contradict each other:");
                foreach (var bad in report.Inconsistent)
                {
                    SystemConsole.Error.WriteLine(
                        $"    group {bad.Share.GroupIndex}, member {bad.Share.MemberIndex}: {bad.Detail}");
                }
                return ExitFailure;
            }

            var unverifiable = report.Unverifiable.ToList();
            if (unverifiable.Count > 0)
            {
                SystemConsole.WriteLine("⚠ Not enough shares to cross-check them against each other:");
                foreach (var byGroup in unverifiable.GroupBy(u => u.Share.GroupIndex))
                {
                    SystemConsole.WriteLine($"    {byGroup.First().Detail}");
                }
                SystemConsole.WriteLine("  Each share is well-formed, but nothing confirms they belong together.");
                return ExitSuccess;
            }

            SystemConsole.WriteLine("✓ They agree with each other and reconstruct a consistent secret.");
            return ExitSuccess;
        }
        catch (ArgumentException ex)
        {
            SystemConsole.Error.WriteLine($"✗ These shares do not form a coherent set: {ex.Message}");
            return ExitFailure;
        }
    }

    static void ShowValidateHelp()
    {
        SystemConsole.WriteLine("Validate Command - Validate SLIP-0039 share checksums");
        SystemConsole.WriteLine("====================================================\n");
        
        SystemConsole.WriteLine("Usage:");
        SystemConsole.WriteLine("  slip39 validate [options] \"share1\" \"share2\" [\"share3\" ...]\n");
        
        SystemConsole.WriteLine("Optional Arguments:");
        SystemConsole.WriteLine("  --verbose         Show detailed validation information\n");

        SystemConsole.WriteLine("Given two or more shares, they are also cross-checked against each other.");
        SystemConsole.WriteLine("A valid checksum only proves one mnemonic was copied without a typo; the");
        SystemConsole.WriteLine("cross-check proves the shares still belong together.\n");

        SystemConsole.WriteLine("Examples:");
        SystemConsole.WriteLine("  slip39 validate \"mild isolate academic acid...\" \"mild isolate academic agency...\"");
        SystemConsole.WriteLine("  slip39 validate --verbose \"share1\" \"share2\" \"share3\"");
    }

    static int HandleGenerateCommand(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help"))
        {
            ShowGenerateHelp();
            return ExitSuccess;
        }

        int bits = 256;
        int threshold = 2;
        int shares = 3;
        string? passphrase = null;
        byte iterationExponent = 0;
        bool extendable = false;
        string outputFormat = "text";
        bool showSecret = false;
        bool showBip32 = false;

        // Parse arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--bits":
                    bits = ParseIntArgument(args, ref i, "--bits");
                    break;
                case "--threshold":
                    threshold = ParseIntArgument(args, ref i, "--threshold");
                    break;
                case "--shares":
                    shares = ParseIntArgument(args, ref i, "--shares");
                    break;
                case "--passphrase":
                    passphrase = GetNextArgument(args, ref i, "--passphrase");
                    break;
                case "--iterations":
                    iterationExponent = ParseByteArgument(args, ref i, "--iterations");
                    break;
                case "--extendable":
                    extendable = true;
                    break;
                case "--format":
                    outputFormat = GetNextArgument(args, ref i, "--format");
                    break;
                case "--show-secret":
                    showSecret = true;
                    break;
                case "--bip32":
                    showBip32 = true;
                    break;
                default:
                    return UnknownOption(args[i], "generate");
            }
        }

        if (bits != 128 && bits != 256)
        {
            SystemConsole.Error.WriteLine("Error: Only 128-bit and 256-bit secrets are supported");
            return ExitFailure;
        }

        byte[]? secret = null;
        try
        {
            // Generate random secret
            secret = new byte[bits / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(secret);
            }

            SystemConsole.WriteLine($"Generated {bits}-bit random secret and split into shares:");
            SystemConsole.WriteLine($"Threshold: {threshold} shares required to recover");
            SystemConsole.WriteLine($"Total shares: {shares}");
            SystemConsole.WriteLine($"Passphrase: {FormatPassphraseDisplay(passphrase)}");
            SystemConsole.WriteLine();

            if (showSecret)
            {
                SystemConsole.WriteLine($"Secret (Hex): {Convert.ToHexString(secret).ToLowerInvariant()}");
                
                if (showBip32)
                {
                    try
                    {
                        string bip32Key = Bip32MasterKey.GenerateMasterKey(secret);
                        SystemConsole.WriteLine($"BIP32 Master Key: {bip32Key}");
                    }
                    catch (Exception ex)
                    {
                        SystemConsole.Error.WriteLine($"Warning: Could not generate BIP32 key: {ex.Message}");
                    }
                }

                SystemConsole.WriteLine();
            }

            var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
            {
                new(threshold, shares)
            };

            var generatedShares = Slip39ShareGeneration.GenerateShares(
                groupThreshold: 1,
                groupConfigs: groupConfigs,
                masterSecret: secret,
                passphrase: passphrase,
                iterationExponent: iterationExponent,
                isExtendable: extendable
            );

            SystemConsole.WriteLine("Generated shares:");
            SystemConsole.WriteLine();

            DisplayGeneratedShares(generatedShares, outputFormat);

            if (!showSecret)
            {
                SystemConsole.WriteLine("Note: Use --show-secret to display the original secret for verification.");
            }

            return ExitSuccess;
        }
        catch (Exception ex)
        {
            SystemConsole.Error.WriteLine($"Error generating shares: {ex.Message}");
            return ExitFailure;
        }
        finally
        {
            if (secret != null) CryptographicOperations.ZeroMemory(secret);
        }
    }

    static int HandleSplitXprivCommand(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help"))
        {
            ShowSplitXprivHelp();
            return ExitSuccess;
        }

        string? xpriv = null;
        int threshold = 2;
        int shares = 3;
        int groupThreshold = 1;
        var groupConfigs = new List<string>();
        string? passphrase = null;
        byte iterationExponent = 0;
        bool extendable = false;
        string outputFormat = "text";
        bool showSecret = false;

        // Parse arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--xpriv":
                    xpriv = GetNextArgument(args, ref i, "--xpriv");
                    break;
                case "--threshold":
                    threshold = ParseIntArgument(args, ref i, "--threshold");
                    break;
                case "--shares":
                    shares = ParseIntArgument(args, ref i, "--shares");
                    break;
                case "--group-threshold":
                    groupThreshold = ParseIntArgument(args, ref i, "--group-threshold");
                    break;
                case "--groups":
                    groupConfigs.Add(GetNextArgument(args, ref i, "--groups"));
                    break;
                case "--passphrase":
                    passphrase = GetNextArgument(args, ref i, "--passphrase");
                    break;
                case "--iterations":
                    iterationExponent = ParseByteArgument(args, ref i, "--iterations");
                    break;
                case "--extendable":
                    extendable = true;
                    break;
                case "--format":
                    outputFormat = GetNextArgument(args, ref i, "--format");
                    break;
                case "--show-secret":
                    showSecret = true;
                    break;
                default:
                    return UnknownOption(args[i], "split-xpriv");
            }
        }

        if (string.IsNullOrEmpty(xpriv))
        {
            SystemConsole.Error.WriteLine("Error: --xpriv is required");
            return ExitFailure;
        }

        byte[]? extendedKeyData = null;
        byte[]? privateKey = null;
        byte[]? chainCode = null;
        byte[]? masterSecret = null;

        try
        {
            // Decode the BIP32 extended private key
            extendedKeyData = Base58Check.Decode(xpriv);

            // Validate BIP32 extended key format
            if (extendedKeyData.Length != 78)
            {
                throw new ArgumentException($"Invalid extended key length: {extendedKeyData.Length} bytes. Expected 78 bytes.");
            }

            // Check version bytes (first 4 bytes) for mainnet private key (0x0488ADE4).
            // This has to be fatal, not a warning: the byte offsets below are only meaningful
            // for an extended *private* key. Given an xpub the old code carried on and printed
            // part of the public key under the label "Private Key", then split it into shares
            // — producing a confident-looking backup of something that cannot restore a wallet.
            var version = new byte[4];
            Array.Copy(extendedKeyData, 0, version, 0, 4);
            var expectedVersion = new byte[] { 0x04, 0x88, 0xAD, 0xE4 };

            if (!version.SequenceEqual(expectedVersion))
            {
                var versionHex = Convert.ToHexString(version);
                SystemConsole.Error.WriteLine($"Error: unexpected version bytes {versionHex}; expected 0488ADE4 for a mainnet xprv.");
                SystemConsole.Error.WriteLine("Only mainnet extended private keys (xprv...) can be split by this command.");
                return ExitFailure;
            }

            // Extract the 32-byte private key (starts at byte 46, after 0x00 prefix at byte 45)
            privateKey = new byte[32];
            Array.Copy(extendedKeyData, 46, privateKey, 0, 32);

            // Extract the 32-byte chain code (bytes 13-44)
            chainCode = new byte[32];
            Array.Copy(extendedKeyData, 13, chainCode, 0, 32);

            // For proper BIP32 reconstruction, we need both the private key and chain code
            // Combine them into a 64-byte secret: private key (32) + chain code (32)
            masterSecret = new byte[64];
            Array.Copy(privateKey, 0, masterSecret, 0, 32);
            Array.Copy(chainCode, 0, masterSecret, 32, 32);

            SystemConsole.WriteLine($"Successfully decoded BIP32 extended private key");

            // The private key and chain code are the whole wallet. Printing them by default
            // put them in the terminal scrollback, in any `tee`, and in any recorded session
            // of a tool whose entire purpose is to avoid exactly that. --show-secret exists
            // for callers who genuinely want to verify the input; it now gates all of it.
            if (showSecret)
            {
                SystemConsole.WriteLine($"Private Key: {Convert.ToHexString(privateKey).ToLowerInvariant()}");
                SystemConsole.WriteLine($"Chain Code: {Convert.ToHexString(chainCode).ToLowerInvariant()}");
                SystemConsole.WriteLine($"Secret to Split: {Convert.ToHexString(masterSecret).ToLowerInvariant()} (private key + chain code)");
            }

            SystemConsole.WriteLine();

            List<Slip39ShareGeneration.GroupConfig> parsedGroupConfigs;
            
            // If groups are specified, use multi-group configuration
            if (groupConfigs.Count > 0)
            {
                parsedGroupConfigs = ParseGroupConfigurations(groupConfigs);
                
                // Validate group threshold
                if (groupThreshold > parsedGroupConfigs.Count)
                {
                    SystemConsole.Error.WriteLine($"Error: Group threshold ({groupThreshold}) cannot exceed number of groups ({parsedGroupConfigs.Count})");
                    return ExitFailure;
                }
            }
            else
            {
                // Single group configuration (backward compatibility)
                parsedGroupConfigs = new List<Slip39ShareGeneration.GroupConfig>
                {
                    new(threshold, shares)
                };
                groupThreshold = 1;
            }

            // For BIP32 keys, the 64-byte secret (private key + chain code) should be treated
            // as a master secret that goes through the normal SLIP-0039 encryption process
            var generatedShares = Slip39ShareGeneration.GenerateShares(
                groupThreshold: groupThreshold,
                groupConfigs: parsedGroupConfigs,
                masterSecret: masterSecret,
                passphrase: passphrase,
                iterationExponent: iterationExponent,
                isExtendable: extendable
            );

            // Display configuration summary
            SystemConsole.WriteLine($"Successfully generated {generatedShares.Count} SLIP-0039 shares from BIP32 key:");
            
            if (parsedGroupConfigs.Count == 1)
            {
                SystemConsole.WriteLine($"Single Group: {threshold} of {shares} shares required to recover");
            }
            else
            {
                SystemConsole.WriteLine($"Multi-Group Configuration: {groupThreshold} groups required out of {parsedGroupConfigs.Count} total groups");
                for (int i = 0; i < parsedGroupConfigs.Count; i++)
                {
                    var config = parsedGroupConfigs[i];
                    SystemConsole.WriteLine($"  Group {i + 1}: {config.MemberThreshold} of {config.MemberCount} shares");
                }
            }
            
            SystemConsole.WriteLine($"Passphrase: {FormatPassphraseDisplay(passphrase)}");
            SystemConsole.WriteLine();

            DisplayGeneratedShares(generatedShares, outputFormat);

            SystemConsole.WriteLine("Note: To recover the original BIP32 key, combine the shares and use the 'combine --bip32' command.");
            return ExitSuccess;
        }
        catch (Exception ex)
        {
            SystemConsole.Error.WriteLine($"Error processing BIP32 extended private key: {ex.Message}");
            return ExitFailure;
        }
        finally
        {
            // Every one of these holds the wallet's private key or a copy of it.
            if (extendedKeyData != null) CryptographicOperations.ZeroMemory(extendedKeyData);
            if (privateKey != null) CryptographicOperations.ZeroMemory(privateKey);
            if (chainCode != null) CryptographicOperations.ZeroMemory(chainCode);
            if (masterSecret != null) CryptographicOperations.ZeroMemory(masterSecret);
        }
    }


    static void ShowSplitXprivHelp()
    {
        SystemConsole.WriteLine("Split-Xpriv Command - Split a BIP32 extended private key into SLIP-0039 shares");
        SystemConsole.WriteLine("===============================================================================\n");
        
        SystemConsole.WriteLine("Usage:");
        SystemConsole.WriteLine("  slip39 split-xpriv --xpriv <xprv...> [options]\n");
        
        SystemConsole.WriteLine("Required Arguments:");
        SystemConsole.WriteLine("  --xpriv <xprv...>   BIP32 extended private key (starts with 'xprv')\n");
        
        SystemConsole.WriteLine("Single Group Mode (Simple):");
        SystemConsole.WriteLine("  --threshold <n>     Number of shares needed to recover (default: 2)");
        SystemConsole.WriteLine("  --shares <n>        Total number of shares to generate (default: 3)\n");
        
        SystemConsole.WriteLine("Multi-Group Mode (Advanced):");
        SystemConsole.WriteLine("  --group-threshold <n>  Number of groups needed to recover (default: 1)");
        SystemConsole.WriteLine("  --groups <config>      Group configurations in format 'threshold-of-total'");
        SystemConsole.WriteLine("                         Examples: \"2-of-3\" or \"2-of-3,3-of-5,1-of-1\"\n");
        
        SystemConsole.WriteLine("Common Options:");
        SystemConsole.WriteLine("  --passphrase <p>    Custom passphrase (default: TREZOR)");
        SystemConsole.WriteLine("  --iterations <n>    Iteration exponent 0-15 (default: 0 = 10,000 iterations)");
        SystemConsole.WriteLine("  --extendable        Generate extendable shares");
        SystemConsole.WriteLine("  --format <fmt>      Output format: text, json, hex (default: text)");
        SystemConsole.WriteLine("  --show-secret       Print the private key, chain code and combined secret.");
        SystemConsole.WriteLine("                      Off by default: these are the wallet itself and would");
        SystemConsole.WriteLine("                      otherwise end up in terminal scrollback and logs.\n");
        
        SystemConsole.WriteLine("Examples:");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # Simple backup of hardware wallet master key:");
        SystemConsole.WriteLine("  slip39 split-xpriv --xpriv xprv9s21ZrQH... --threshold 2 --shares 3");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # Multi-signature wallet backup:");
        SystemConsole.WriteLine("  slip39 split-xpriv --xpriv xprv9s21ZrQH... --group-threshold 2 --groups \"2-of-3,3-of-5\"");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # Corporate backup with custom passphrase:");
        SystemConsole.WriteLine("  slip39 split-xpriv --xpriv xprv9s21ZrQH... --groups \"3-of-5\" --passphrase corp2024");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("Note: The resulting shares can be combined using 'slip39 combine --bip32' to reconstruct the original xprv.");
    }

    static void ShowGenerateHelp()
    {
        SystemConsole.WriteLine("Generate Command - Generate random secret and split into shares");
        SystemConsole.WriteLine("===============================================================\n");
        
        SystemConsole.WriteLine("Usage:");
        SystemConsole.WriteLine("  slip39 generate [options]\n");
        
        SystemConsole.WriteLine("Optional Arguments:");
        SystemConsole.WriteLine("  --bits \u003cn\u003e         Secret size in bits: 128 or 256 (default: 256)");
        SystemConsole.WriteLine("  --threshold \u003cn\u003e    Number of shares needed to recover (default: 2)");
        SystemConsole.WriteLine("  --shares \u003cn\u003e       Total number of shares to generate (default: 3)");
        SystemConsole.WriteLine("  --passphrase \u003cp\u003e   Custom passphrase (default: TREZOR)");
        SystemConsole.WriteLine("  --iterations \u003cn\u003e   Iteration exponent 0-15 (default: 0 = 10,000 iterations)");
        SystemConsole.WriteLine("  --extendable       Generate extendable shares");
        SystemConsole.WriteLine("  --format \u003cfmt\u003e     Output format: text, json, hex (default: text)");
        SystemConsole.WriteLine("  --show-secret      Display the generated secret (for verification)");
        SystemConsole.WriteLine("  --bip32            Also show BIP32 master key\n");
        
        SystemConsole.WriteLine("Examples:");
        SystemConsole.WriteLine("  slip39 generate");
        SystemConsole.WriteLine("  slip39 generate --bits 128 --threshold 3 --shares 5");
        SystemConsole.WriteLine("  slip39 generate --show-secret --bip32");
        SystemConsole.WriteLine("  slip39 generate --passphrase mypass --format json");
    }

    // Helper methods for argument parsing
    static string GetNextArgument(string[] args, ref int index, string paramName)
    {
        if (index + 1 >= args.Length)
            throw new ArgumentException($"Missing value for {paramName}");
        return args[++index];
    }

    static int ParseIntArgument(string[] args, ref int index, string paramName)
    {
        string value = GetNextArgument(args, ref index, paramName);
        if (!int.TryParse(value, out int result))
            throw new ArgumentException($"Invalid integer value for {paramName}: {value}");
        return result;
    }

    static byte ParseByteArgument(string[] args, ref int index, string paramName)
    {
        string value = GetNextArgument(args, ref index, paramName);
        if (!byte.TryParse(value, out byte result))
            throw new ArgumentException($"Invalid byte value for {paramName}: {value}");
        return result;
    }

    static string FormatShareOutput(Slip39Share share, string format)
    {
        return format.ToLowerInvariant() switch
        {
            "json" => Slip39ShareParser.ToJson(share),
            "hex" => share.ToHex(),
            _ => share.ToMnemonic()
        };
    }

    static string FormatPassphraseDisplay(string? passphrase)
    {
        return string.IsNullOrEmpty(passphrase) ? "TREZOR (default)" : "[custom]";
    }

    static void DisplayGeneratedShares(List<Slip39Share> shares, string outputFormat)
    {
        // Group shares by group for better display
        var sharesByGroup = shares.GroupBy(s => s.GroupIndex).OrderBy(g => g.Key).ToList();
        
        foreach (var group in sharesByGroup)
        {
            bool isMultiGroup = sharesByGroup.Count > 1;
            if (isMultiGroup)
            {
                SystemConsole.WriteLine($"Group {group.Key + 1} shares:");
            }
            
            foreach (var share in group.OrderBy(s => s.MemberIndex))
            {
                string prefix = isMultiGroup ? "  " : "";
                SystemConsole.WriteLine($"{prefix}Share {share.MemberIndex + 1}:");
                
                string shareOutput = FormatShareOutput(share, outputFormat);
                SystemConsole.WriteLine($"{prefix}{shareOutput}");
                SystemConsole.WriteLine();
            }
            
            if (isMultiGroup)
            {
                SystemConsole.WriteLine();
            }
        }
    }
}
