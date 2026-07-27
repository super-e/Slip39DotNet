namespace Slip39.Core;

/// <summary>
/// Provides arithmetic operations in the Galois Field GF(256) using the irreducible polynomial x^8 + x^4 + x^3 + x + 1.
/// This implementation prioritizes clarity and correctness over performance optimization.
/// </summary>
public static class GaloisField256
{
    /// <summary>
    /// The irreducible polynomial used for GF(256): x^8 + x^4 + x^3 + x + 1 = 0x11B
    /// This is the same polynomial used in AES encryption.
    /// </summary>
    private const int IrreduciblePolynomial = 0x11B;

    /// <summary>
    /// Precomputed logarithm table for efficient multiplication and division.
    /// logarithmTable[i] = log_3(i) where 3 is the generator for GF(256).
    /// </summary>
    private static readonly byte[] LogarithmTable = new byte[256];

    /// <summary>
    /// Precomputed exponential table for efficient multiplication and division.
    /// exponentialTable[i] = 3^i mod IrreduciblePolynomial.
    /// </summary>
    private static readonly byte[] ExponentialTable = new byte[256];

    /// <summary>
    /// Static constructor to initialize the logarithm and exponential lookup tables.
    /// </summary>
    static GaloisField256()
    {
        InitializeLookupTables();
    }

    /// <summary>
    /// Adds two elements in GF(256). In Galois Fields with characteristic 2,
    /// addition is equivalent to the XOR operation.
    /// </summary>
    /// <param name="firstElement">The first element to add</param>
    /// <param name="secondElement">The second element to add</param>
    /// <returns>The sum of the two elements in GF(256)</returns>
    public static byte Add(byte firstElement, byte secondElement)
    {
        return (byte)(firstElement ^ secondElement);
    }

    /// <summary>
    /// Subtracts two elements in GF(256). In Galois Fields with characteristic 2,
    /// subtraction is equivalent to addition, which is the XOR operation.
    /// </summary>
    /// <param name="minuend">The element to subtract from</param>
    /// <param name="subtrahend">The element to subtract</param>
    /// <returns>The difference of the two elements in GF(256)</returns>
    public static byte Subtract(byte minuend, byte subtrahend)
    {
        // In GF(2^n), subtraction is the same as addition
        return Add(minuend, subtrahend);
    }

    /// <summary>
    /// Multiplies two elements in GF(256) using precomputed logarithm and exponential tables
    /// for efficiency while maintaining clarity.
    /// </summary>
    /// <param name="firstFactor">The first factor</param>
    /// <param name="secondFactor">The second factor</param>
    /// <returns>The product of the two elements in GF(256)</returns>
    public static byte Multiply(byte firstFactor, byte secondFactor)
    {
        // Handle multiplication by zero
        if (firstFactor == 0 || secondFactor == 0)
        {
            return 0;
        }

        // Use logarithm properties: log(a * b) = log(a) + log(b)
        int logarithmSum = LogarithmTable[firstFactor] + LogarithmTable[secondFactor];
        
        // Handle overflow by wrapping around (since we're in GF(2^8), the period is 255)
        if (logarithmSum >= 255)
        {
            logarithmSum -= 255;
        }

        return ExponentialTable[logarithmSum];
    }

    /// <summary>
    /// Divides two elements in GF(256). Division by zero is undefined and will throw an exception.
    /// </summary>
    /// <param name="dividend">The element to be divided</param>
    /// <param name="divisor">The element to divide by</param>
    /// <returns>The quotient of the division in GF(256)</returns>
    /// <exception cref="DivideByZeroException">Thrown when attempting to divide by zero</exception>
    public static byte Divide(byte dividend, byte divisor)
    {
        if (divisor == 0)
        {
            throw new DivideByZeroException("Division by zero is undefined in GF(256)");
        }

        if (dividend == 0)
        {
            return 0;
        }

        // Use logarithm properties: log(a / b) = log(a) - log(b)
        int logarithmDifference = LogarithmTable[dividend] - LogarithmTable[divisor];
        
        // Handle underflow by wrapping around
        if (logarithmDifference < 0)
        {
            logarithmDifference += 255;
        }

        return ExponentialTable[logarithmDifference];
    }

    /// <summary>
    /// Computes the multiplicative inverse of an element in GF(256).
    /// The inverse of x is the element y such that x * y = 1.
    /// </summary>
    /// <param name="element">The element to find the inverse of</param>
    /// <returns>The multiplicative inverse of the element</returns>
    /// <exception cref="ArgumentException">Thrown when attempting to find the inverse of zero</exception>
    public static byte MultiplicativeInverse(byte element)
    {
        if (element == 0)
        {
            throw new ArgumentException("Zero has no multiplicative inverse in GF(256)", nameof(element));
        }

        if (element == 1)
        {
            return 1; // The inverse of 1 is 1
        }

        // The inverse of x is 3^(255 - log_3(x))
        int inverseLogarithm = 255 - LogarithmTable[element];
        return ExponentialTable[inverseLogarithm];
    }

    /// <summary>
    /// Raises an element to a power in GF(256).
    /// </summary>
    /// <param name="baseElement">The base element</param>
    /// <param name="exponent">The exponent (non-negative)</param>
    /// <returns>The result of baseElement^exponent in GF(256)</returns>
    /// <exception cref="ArgumentException">Thrown when the exponent is negative</exception>
    public static byte Power(byte baseElement, int exponent)
    {
        if (exponent < 0)
        {
            throw new ArgumentException("Exponent must be non-negative", nameof(exponent));
        }

        if (exponent == 0)
        {
            return 1; // Any number to the power of 0 is 1
        }

        if (baseElement == 0)
        {
            return 0; // 0 to any positive power is 0
        }

        // Use logarithm properties: log(a^n) = n * log(a).
        // The exponent is reduced first: the multiplicative group of GF(256) has order 255, so
        // a^n = a^(n mod 255) for a != 0. Multiplying before reducing overflowed int for large
        // exponents — the product went negative, `%` kept the sign, and the negative index threw.
        int logarithmProduct = (LogarithmTable[baseElement] * (exponent % 255)) % 255;
        return ExponentialTable[logarithmProduct];
    }

    /// <summary>
    /// Initializes the logarithm and exponential lookup tables using the generator 3.
    /// This method is called once during static initialization.
    /// </summary>
    private static void InitializeLookupTables()
    {
        const byte generator = 3; // Generator element for GF(256)
        byte currentPower = 1;

        // Initialize both tables simultaneously
        for (int exponent = 0; exponent < 255; exponent++)
        {
            ExponentialTable[exponent] = currentPower;
            LogarithmTable[currentPower] = (byte)exponent;

            // Compute the next power: currentPower = currentPower * generator
            currentPower = MultiplyWithoutTables(currentPower, generator);
        }

        // Handle the special case for logarithm of 0 (undefined, but we set it to 0 for safety)
        LogarithmTable[0] = 0;
    }

    /// <summary>
    /// Multiplies two elements in GF(256) without using lookup tables.
    /// This method is used during table initialization and for educational purposes.
    /// </summary>
    /// <param name="firstFactor">The first factor</param>
    /// <param name="secondFactor">The second factor</param>
    /// <returns>The product of the two elements in GF(256)</returns>
    private static byte MultiplyWithoutTables(byte firstFactor, byte secondFactor)
    {
        int result = 0;
        int currentFactor = firstFactor;

        // Perform binary multiplication
        for (int bitPosition = 0; bitPosition < 8; bitPosition++)
        {
            // If the corresponding bit in secondFactor is set, add currentFactor to result
            if ((secondFactor & (1 << bitPosition)) != 0)
            {
                result ^= currentFactor;
            }

            // Shift currentFactor left (multiply by x)
            currentFactor <<= 1;

            // If overflow occurred (bit 8 is set), reduce by the irreducible polynomial
            if ((currentFactor & 0x100) != 0)
            {
                currentFactor ^= IrreduciblePolynomial;
            }
        }

        return (byte)result;
    }
}
