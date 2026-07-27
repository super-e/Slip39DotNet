using Slip39.Core;

namespace Slip39.Core.Tests;

/// <summary>
/// Unit tests for the GaloisField256 class to verify correctness of GF(256) arithmetic operations.
/// </summary>
public class GaloisField256Tests
{
    [Fact]
    public void Add_ZeroToAnyElement_ReturnsElement()
    {
        // Test the additive identity property: a + 0 = a
        for (byte element = 0; element < 255; element++)
        {
            var result = GaloisField256.Add(element, 0);
            Assert.Equal(element, result);
        }
    }

    [Fact]
    public void Add_ElementToItself_ReturnsZero()
    {
        // Test that a + a = 0 in GF(256)
        for (byte element = 0; element < 255; element++)
        {
            var result = GaloisField256.Add(element, element);
            Assert.Equal(0, result);
        }
    }

    [Fact]
    public void Add_IsCommutative()
    {
        // Test that a + b = b + a
        for (byte firstElement = 1; firstElement <= 10; firstElement++)
        {
            for (byte secondElement = 1; secondElement <= 10; secondElement++)
            {
                var result1 = GaloisField256.Add(firstElement, secondElement);
                var result2 = GaloisField256.Add(secondElement, firstElement);
                Assert.Equal(result1, result2);
            }
        }
    }

    [Fact]
    public void Subtract_SameAsAdd()
    {
        // In GF(256), subtraction is the same as addition
        for (byte firstElement = 1; firstElement <= 10; firstElement++)
        {
            for (byte secondElement = 1; secondElement <= 10; secondElement++)
            {
                var addResult = GaloisField256.Add(firstElement, secondElement);
                var subtractResult = GaloisField256.Subtract(firstElement, secondElement);
                Assert.Equal(addResult, subtractResult);
            }
        }
    }

    [Fact]
    public void Multiply_ByZero_ReturnsZero()
    {
        // Test that a * 0 = 0
        for (byte element = 1; element < 255; element++)
        {
            var result = GaloisField256.Multiply(element, 0);
            Assert.Equal(0, result);
        }
    }

    [Fact]
    public void Multiply_ByOne_ReturnsElement()
    {
        // Test the multiplicative identity property: a * 1 = a
        for (byte element = 1; element < 255; element++)
        {
            var result = GaloisField256.Multiply(element, 1);
            Assert.Equal(element, result);
        }
    }

    [Fact]
    public void Multiply_IsCommutative()
    {
        // Test that a * b = b * a
        for (byte firstElement = 1; firstElement <= 10; firstElement++)
        {
            for (byte secondElement = 1; secondElement <= 10; secondElement++)
            {
                var result1 = GaloisField256.Multiply(firstElement, secondElement);
                var result2 = GaloisField256.Multiply(secondElement, firstElement);
                Assert.Equal(result1, result2);
            }
        }
    }

    [Theory]
    [InlineData(2, 3, 6)]     // Simple case
    [InlineData(5, 7, 27)]    // Correct value in our GF(256) implementation
    [InlineData(255, 1, 255)] // Edge case with maximum value
    public void Multiply_KnownValues_ReturnsExpectedResults(byte firstFactor, byte secondFactor, byte expectedResult)
    {
        var result = GaloisField256.Multiply(firstFactor, secondFactor);
        Assert.Equal(expectedResult, result);
    }

    [Fact]
    public void Divide_ByZero_ThrowsException()
    {
        Assert.Throws<DivideByZeroException>(() => GaloisField256.Divide(5, 0));
    }

    [Fact]
    public void Divide_ZeroByAnyNonZero_ReturnsZero()
    {
        for (byte divisor = 1; divisor < 255; divisor++)
        {
            var result = GaloisField256.Divide(0, divisor);
            Assert.Equal(0, result);
        }
    }

    [Fact]
    public void Divide_ElementByItself_ReturnsOne()
    {
        // Test that a / a = 1 for all non-zero a
        for (byte element = 1; element <= 20; element++)
        {
            var result = GaloisField256.Divide(element, element);
            Assert.Equal(1, result);
        }
    }

    [Fact]
    public void Divide_ElementByOne_ReturnsElement()
    {
        // Test that a / 1 = a
        for (byte element = 1; element <= 20; element++)
        {
            var result = GaloisField256.Divide(element, 1);
            Assert.Equal(element, result);
        }
    }

    [Fact]
    public void MultiplyThenDivide_ReturnsOriginalValue()
    {
        // Test that (a * b) / b = a for non-zero values
        for (byte firstElement = 1; firstElement <= 10; firstElement++)
        {
            for (byte secondElement = 1; secondElement <= 10; secondElement++)
            {
                var product = GaloisField256.Multiply(firstElement, secondElement);
                var quotient = GaloisField256.Divide(product, secondElement);
                Assert.Equal(firstElement, quotient);
            }
        }
    }

    [Fact]
    public void MultiplicativeInverse_OfZero_ThrowsException()
    {
        Assert.Throws<ArgumentException>(() => GaloisField256.MultiplicativeInverse(0));
    }

    [Fact]
    public void MultiplicativeInverse_MultiplyWithOriginal_ReturnsOne()
    {
        // Test that a * a^(-1) = 1 for all non-zero a
        for (byte element = 1; element <= 20; element++)
        {
            var inverse = GaloisField256.MultiplicativeInverse(element);
            var product = GaloisField256.Multiply(element, inverse);
            Assert.Equal(1, product);
        }
    }

    [Theory]
    [InlineData(1, 1)]   // 1^(-1) = 1
    [InlineData(2, 141)] // Known inverse pairs for our GF(256) implementation
    [InlineData(3, 246)]
    public void MultiplicativeInverse_KnownValues_ReturnsExpectedResults(byte element, byte expectedInverse)
    {
        var inverse = GaloisField256.MultiplicativeInverse(element);
        Assert.Equal(expectedInverse, inverse);
    }

    [Fact]
    public void Power_ToZero_ReturnsOne()
    {
        // Test that a^0 = 1 for all a
        for (byte element = 1; element <= 10; element++)
        {
            var result = GaloisField256.Power(element, 0);
            Assert.Equal(1, result);
        }
    }

    [Fact]
    public void Power_ToOne_ReturnsElement()
    {
        // Test that a^1 = a
        for (byte element = 1; element <= 10; element++)
        {
            var result = GaloisField256.Power(element, 1);
            Assert.Equal(element, result);
        }
    }

    [Fact]
    public void Power_OfZero_ReturnsZero()
    {
        // Test that 0^n = 0 for positive n
        for (int exponent = 1; exponent <= 5; exponent++)
        {
            var result = GaloisField256.Power(0, exponent);
            Assert.Equal(0, result);
        }
    }

    [Fact]
    public void Power_NegativeExponent_ThrowsException()
    {
        Assert.Throws<ArgumentException>(() => GaloisField256.Power(2, -1));
    }

    [Theory]
    [InlineData(2, 2, 4)]     // 2^2 = 4
    [InlineData(2, 3, 8)]     // 2^3 = 8
    [InlineData(3, 2, 5)]     // 3^2 = 5 in our GF(256) implementation
    [InlineData(2, 8, 27)]    // 2^8 = 27 in our GF(256) implementation
    public void Power_KnownValues_ReturnsExpectedResults(byte baseElement, int exponent, byte expectedResult)
    {
        var result = GaloisField256.Power(baseElement, exponent);
        Assert.Equal(expectedResult, result);
    }

    [Theory]
    [InlineData(246, 8455448)]        // log(246) = 254, so the product used to overflow int here
    [InlineData(246, int.MaxValue)]
    [InlineData(255, 1000000)]
    [InlineData(3, 2000000000)]
    public void Power_LargeExponent_MatchesRepeatedMultiplication(byte baseElement, int exponent)
    {
        // a^n = a^(n mod 255) for a != 0: the multiplicative group of GF(256) has order 255.
        byte expected = 1;
        for (int i = 0; i < exponent % 255; i++)
        {
            expected = GaloisField256.Multiply(expected, baseElement);
        }

        Assert.Equal(expected, GaloisField256.Power(baseElement, exponent));
    }

    [Fact]
    public void Power_ToTheGroupOrder_ReturnsOne()
    {
        // a^255 = 1 for every non-zero a, which is what makes reducing the exponent sound.
        for (int element = 1; element <= 255; element++)
        {
            Assert.Equal(1, GaloisField256.Power((byte)element, 255));
        }
    }

    [Fact]
    public void FieldOperations_SatisfyDistributiveProperty()
    {
        // Test that a * (b + c) = (a * b) + (a * c)
        for (byte a = 1; a <= 5; a++)
        {
            for (byte b = 1; b <= 5; b++)
            {
                for (byte c = 1; c <= 5; c++)
                {
                    var leftSide = GaloisField256.Multiply(a, GaloisField256.Add(b, c));
                    var rightSide = GaloisField256.Add(
                        GaloisField256.Multiply(a, b),
                        GaloisField256.Multiply(a, c));
                    
                    Assert.Equal(leftSide, rightSide);
                }
            }
        }
    }

    [Fact]
    public void Generator_CreatesAllNonZeroElements()
    {
        // Test that powers of the generator 3 produce all non-zero elements
        var generatedElements = new HashSet<byte>();
        byte currentPower = 1;

        for (int exponent = 0; exponent < 255; exponent++)
        {
            generatedElements.Add(currentPower);
            currentPower = GaloisField256.Multiply(currentPower, 3);
        }

        // Should have generated all 255 non-zero elements
        Assert.Equal(255, generatedElements.Count);
        Assert.DoesNotContain((byte)0, generatedElements); // Zero should not be generated
    }

    [Fact]
    public void Addition_IsAssociative()
    {
        // Test that (a + b) + c = a + (b + c)
        for (byte a = 1; a <= 5; a++)
        {
            for (byte b = 1; b <= 5; b++)
            {
                for (byte c = 1; c <= 5; c++)
                {
                    var leftSide = GaloisField256.Add(GaloisField256.Add(a, b), c);
                    var rightSide = GaloisField256.Add(a, GaloisField256.Add(b, c));
                    Assert.Equal(leftSide, rightSide);
                }
            }
        }
    }

    [Fact]
    public void Multiplication_IsAssociative()
    {
        // Test that (a * b) * c = a * (b * c)
        for (byte a = 1; a <= 5; a++)
        {
            for (byte b = 1; b <= 5; b++)
            {
                for (byte c = 1; c <= 5; c++)
                {
                    var leftSide = GaloisField256.Multiply(GaloisField256.Multiply(a, b), c);
                    var rightSide = GaloisField256.Multiply(a, GaloisField256.Multiply(b, c));
                    Assert.Equal(leftSide, rightSide);
                }
            }
        }
    }
}
