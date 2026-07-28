using System.Linq;

namespace Slip39.Core;

/// <summary>
/// Main class for SLIP-0039 Shamir's Secret Sharing implementation
/// </summary>
public static class Slip39
{
    /// <summary>
    /// Combines multiple mnemonic shares to recover the master secret
    /// </summary>
    /// <param name="mnemonics">Array of mnemonic strings to combine</param>
    /// <returns>Result containing the master secret or error information</returns>
    public static CombineResult CombineMnemonics(string[] mnemonics)
    {
        return CombineMnemonics(mnemonics, null);
    }

    /// <summary>
    /// Combines multiple mnemonic shares to recover the master secret with a passphrase
    /// </summary>
    /// <param name="mnemonics">Array of mnemonic strings to combine</param>
    /// <param name="passphrase">Passphrase for decryption</param>
    /// <returns>Result containing the master secret or error information</returns>
    public static CombineResult CombineMnemonics(string[] mnemonics, string? passphrase)
    {
        try
        {
            if (mnemonics == null)
                return CombineResult.Failure("Mnemonics array cannot be null");
            
            if (mnemonics.Length == 0)
                return CombineResult.Failure("At least one mnemonic is required");
            
            // Parse all mnemonics into shares
            var shares = new List<Slip39Share>();
            foreach (var mnemonic in mnemonics)
            {
                if (string.IsNullOrWhiteSpace(mnemonic))
                    return CombineResult.Failure("Invalid mnemonic: empty or null");
                
                try
                {
                    var share = Slip39ShareParser.ParseFromMnemonic(mnemonic);
                    shares.Add(share);
                }
                catch (Exception ex)
                {
                    return CombineResult.Failure($"Failed to parse mnemonic: {ex.Message}");
                }
            }
            
            // Use the correct SLIP-0039 share combination implementation
            var masterSecret = Slip39ShareCombination.CombineShares(shares, passphrase);
            
            // Get the normalized passphrase that was actually used (null/empty means no passphrase)
            var normalizedPassphraseBytes = Slip39Passphrase.NormalizePassphrase(passphrase);
            var actualPassphrase = System.Text.Encoding.UTF8.GetString(normalizedPassphraseBytes);
            
            return CombineResult.Success(masterSecret, actualPassphrase);
        }
        catch (ArgumentException ex)
        {
            return CombineResult.Failure(ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            return CombineResult.Failure(ex.Message);
        }
        catch (Exception ex)
        {
            return CombineResult.Failure($"Unexpected error: {ex.Message}");
        }
    }

    /// <summary>
    /// Generates a BIP32 extended private key from the master secret and passphrase according to SLIP-0039 specification.
    /// </summary>
    /// <param name="masterSecret">The recovered master secret</param>
    /// <param name="passphrase">Optional passphrase for key derivation (null or empty means no passphrase)</param>
    /// <returns>BIP32 extended private key in Base58Check format (xprv...)</returns>
    public static string GenerateMasterKey(byte[] masterSecret, string? passphrase = null)
    {
        // Use the proper BIP32 master key derivation implementation
        return Bip32MasterKey.GenerateMasterKey(masterSecret, passphrase);
    }
}

/// <summary>
/// Result of combining mnemonic shares
/// </summary>
public class CombineResult
{
    /// <summary>
    /// Indicates if the combination was successful
    /// </summary>
    public bool IsSuccess { get; set; }

    /// <summary>
    /// The recovered master secret (only valid if IsSuccess is true)
    /// </summary>
    public byte[] MasterSecret { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Optional passphrase used in the recovery process
    /// </summary>
    public string? Passphrase { get; set; }

    /// <summary>
    /// Error message if the combination failed
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Creates a successful result
    /// </summary>
    public static CombineResult Success(byte[] masterSecret, string? passphrase = null)
    {
        return new CombineResult
        {
            IsSuccess = true,
            MasterSecret = masterSecret,
            Passphrase = passphrase
        };
    }

    /// <summary>
    /// Creates a failed result
    /// </summary>
    public static CombineResult Failure(string errorMessage)
    {
        return new CombineResult
        {
            IsSuccess = false,
            ErrorMessage = errorMessage
        };
    }
}
