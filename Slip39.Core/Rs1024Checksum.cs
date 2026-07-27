namespace Slip39.Core;

/// <summary>
/// Implements the RS1024 checksum algorithm used in SLIP-0039 for mnemonic validation.
/// Based on the Reed-Solomon error correction code over GF(1024).
/// </summary>
public static class Rs1024Checksum
{
    /// <summary>
    /// The RS1024 generator polynomial coefficients as specified in SLIP-0039
    /// These values are from the Trezor python-shamir-mnemonic reference implementation
    /// </summary>
    private static readonly uint[] GeneratorCoefficients = new uint[]
    {
        0xe0e040,
        0x1c1c080, 
        0x3838100,
        0x7070200,
        0xe0e0009,
        0x1c0c2412,
        0x38086c24,
        0x3090fc48,
        0x21b1f890,
        0x3f3f120
    };

    /// <summary>
    /// The customization string for non-extendable SLIP-0039 shares
    /// </summary>
    private const string Slip39CustomizationString = "shamir";
    
    /// <summary>
    /// The customization string for extendable SLIP-0039 shares
    /// </summary>
    private const string Slip39ExtendableCustomizationString = "shamir_extendable";

    /// <summary>
    /// Verifies the RS1024 checksum of a SLIP-0039 mnemonic.
    /// </summary>
    /// <param name="values">The 10-bit word values of the mnemonic (including checksum)</param>
    /// <param name="isExtendable">Whether this is an extendable share (affects customization string)</param>
    /// <returns>True if the checksum is valid, false otherwise</returns>
    public static bool VerifyChecksum(ushort[] values, bool isExtendable = false)
    {
        if (values == null)
            throw new ArgumentNullException(nameof(values));
        
        if (values.Length < 3) // Minimum mnemonic length
            throw new ArgumentException("Mnemonic must have at least 3 words");

        // All values must be in the range [0, 1023]
        foreach (var value in values)
        {
            if (value >= 1024)
                throw new ArgumentException($"All word values must be less than 1024, got {value}");
        }

        return CalculateChecksum(values, isExtendable) == 1;
    }

    /// <summary>
    /// Calculates the RS1024 checksum for the given values.
    /// </summary>
    /// <param name="values">The 10-bit word values</param>
    /// <param name="isExtendable">Whether this is an extendable share (affects customization string)</param>
    /// <returns>The checksum value (should be 1 for valid mnemonics)</returns>
    public static uint CalculateChecksum(ushort[] values, bool isExtendable = false)
    {
        if (values == null)
            throw new ArgumentNullException(nameof(values));

        // Initialize with the appropriate customization string
        string customizationString = isExtendable ? Slip39ExtendableCustomizationString : Slip39CustomizationString;
        uint checksum = CalculateCustomizationValue(customizationString);

        // Process each value
        foreach (var value in values)
        {
            checksum = UpdateChecksum(checksum, value);
        }

        return checksum;
    }

    /// <summary>
    /// Generates the 3-word checksum for a given data portion of a mnemonic.
    /// Uses the proper Reed-Solomon polynomial division algorithm.
    /// </summary>
    /// <param name="dataValues">The data portion of the mnemonic (without checksum)</param>
    /// <param name="isExtendable">Whether this is an extendable share (affects customization string)</param>
    /// <returns>The 3-word checksum</returns>
    public static ushort[] GenerateChecksum(ushort[] dataValues, bool isExtendable = false)
    {
        if (dataValues == null)
            throw new ArgumentNullException(nameof(dataValues));

        // Start with the appropriate customization string
        string customizationString = isExtendable ? Slip39ExtendableCustomizationString : Slip39CustomizationString;
        uint checksum = CalculateCustomizationValue(customizationString);
        
        // Process all data values
        foreach (var value in dataValues)
        {
            checksum = UpdateChecksum(checksum, value);
        }
        
        // For standard Reed-Solomon, we need to multiply by x^(checksum_length)
        // This is equivalent to processing zeros for each checksum position
        for (int i = 0; i < 3; i++)
        {
            checksum = UpdateChecksum(checksum, 0);
        }
        
        // Now we have the syndrome. For SLIP-39, we want the final result to be 1,
        // so we need to find the checksum that makes (data || checksum) evaluate to 1
        // This means we need: current_checksum XOR checksum_to_add = 1
        // Therefore: checksum_to_add = current_checksum XOR 1
        uint targetChecksum = checksum ^ 1;
        
        // Extract the checksum words (reverse order to match Trezor reference implementation)
        var checksumWords = new ushort[3];
        checksumWords[0] = (ushort)((targetChecksum >> 20) & 0x3FF);   // bits 20-29 first
        checksumWords[1] = (ushort)((targetChecksum >> 10) & 0x3FF);   // bits 10-19 second
        checksumWords[2] = (ushort)(targetChecksum & 0x3FF);           // bits 0-9 last

        return checksumWords;
    }

    /// <summary>
    /// Calculates the customization value for the given string.
    /// </summary>
    /// <param name="customization">The customization string</param>
    /// <returns>The customization value</returns>
    private static uint CalculateCustomizationValue(string customization)
    {
        uint value = 1;
        
        foreach (char c in customization)
        {
            value = UpdateChecksum(value, (ushort)c);
        }
        
        return value;
    }

    /// <summary>
    /// Updates the checksum with a new value using the RS1024 algorithm (polymod).
    /// This matches the rs1024_polymod function from the SLIP-0039 specification.
    /// </summary>
    /// <param name="checksum">Current checksum value</param>
    /// <param name="value">New value to process</param>
    /// <returns>Updated checksum</returns>
    private static uint UpdateChecksum(uint checksum, ushort value)
    {
        uint b = checksum >> 20;
        checksum = (checksum & 0xfffff) << 10 ^ value;
        
        for (int i = 0; i < 10; i++)
        {
            if ((b & (1u << i)) != 0)
            {
                checksum ^= GeneratorCoefficients[i];
            }
        }
        
        return checksum;
    }

}
