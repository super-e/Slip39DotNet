using System;
using System.IO;
using System.Linq;
using Xunit;
using Slip39.Core;

namespace Slip39.Core.Tests
{
    public class WordlistTests
    {
        [Fact]
        public void WordCount_ShouldBe1024()
        {
            // Act
            var count = Wordlist.WordCount;

            // Assert
            Assert.Equal(1024, count);
        }

        [Fact]
        public void Words_ShouldContain1024Words()
        {
            // Act
            var words = Wordlist.Words;

            // Assert
            Assert.Equal(1024, words.Count);
            Assert.True(words.All(w => !string.IsNullOrEmpty(w)));
        }

        [Fact]
        public void GetWord_WithValidIndex_ShouldReturnCorrectWord()
        {
            // Act & Assert
            Assert.Equal("academic", Wordlist.GetWord(0));
            Assert.Equal("acid", Wordlist.GetWord(1));
            Assert.Equal("zero", Wordlist.GetWord(1023));
        }

        [Fact]
        public void GetWord_WithNegativeIndex_ShouldThrowArgumentOutOfRangeException()
        {
            // Act & Assert
            Assert.Throws<ArgumentOutOfRangeException>(() => Wordlist.GetWord(-1));
        }

        [Fact]
        public void GetWord_WithIndexTooLarge_ShouldThrowArgumentOutOfRangeException()
        {
            // Act & Assert
            Assert.Throws<ArgumentOutOfRangeException>(() => Wordlist.GetWord(1024));
        }

        [Fact]
        public void GetIndex_WithValidWord_ShouldReturnCorrectIndex()
        {
            // Act & Assert
            Assert.Equal(0, Wordlist.GetIndex("academic"));
            Assert.Equal(1, Wordlist.GetIndex("acid"));
            Assert.Equal(1023, Wordlist.GetIndex("zero"));
        }

        [Fact]
        public void GetIndex_WithValidWordDifferentCase_ShouldReturnCorrectIndex()
        {
            // Act & Assert
            Assert.Equal(0, Wordlist.GetIndex("ACADEMIC"));
            Assert.Equal(1, Wordlist.GetIndex("Acid"));
            Assert.Equal(1023, Wordlist.GetIndex("Zero"));
        }

        [Fact]
        public void GetIndex_WithInvalidWord_ShouldThrowArgumentException()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() => Wordlist.GetIndex("invalidword"));
        }

        [Fact]
        public void GetIndex_WithNullWord_ShouldThrowArgumentException()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() => Wordlist.GetIndex(null));
        }

        [Fact]
        public void GetIndex_WithEmptyWord_ShouldThrowArgumentException()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() => Wordlist.GetIndex(""));
        }

        [Fact]
        public void GetIndex_WithWhitespaceWord_ShouldThrowArgumentException()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() => Wordlist.GetIndex("   "));
        }

        [Fact]
        public void ContainsWord_WithValidWord_ShouldReturnTrue()
        {
            // Act & Assert
            Assert.True(Wordlist.ContainsWord("academic"));
            Assert.True(Wordlist.ContainsWord("acid"));
            Assert.True(Wordlist.ContainsWord("zero"));
        }

        [Fact]
        public void ContainsWord_WithValidWordDifferentCase_ShouldReturnTrue()
        {
            // Act & Assert
            Assert.True(Wordlist.ContainsWord("ACADEMIC"));
            Assert.True(Wordlist.ContainsWord("Acid"));
            Assert.True(Wordlist.ContainsWord("Zero"));
        }

        [Fact]
        public void ContainsWord_WithInvalidWord_ShouldReturnFalse()
        {
            // Act & Assert
            Assert.False(Wordlist.ContainsWord("invalidword"));
        }

        [Fact]
        public void ContainsWord_WithNullWord_ShouldReturnFalse()
        {
            // Act & Assert
            Assert.False(Wordlist.ContainsWord(null));
        }

        [Fact]
        public void ContainsWord_WithEmptyWord_ShouldReturnFalse()
        {
            // Act & Assert
            Assert.False(Wordlist.ContainsWord(""));
        }

        [Fact]
        public void ContainsWord_WithWhitespaceWord_ShouldReturnFalse()
        {
            // Act & Assert
            Assert.False(Wordlist.ContainsWord("   "));
        }

        [Fact]
        public void ValidateWords_WithValidWords_ShouldReturnTrue()
        {
            // Arrange
            var words = new[] { "academic", "acid", "acne", "acquire" };

            // Act
            var result = Wordlist.ValidateWords(words);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void ValidateWords_WithSomeInvalidWords_ShouldReturnFalse()
        {
            // Arrange
            var words = new[] { "academic", "invalidword", "acid" };

            // Act
            var result = Wordlist.ValidateWords(words);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void ValidateWords_WithNullCollection_ShouldReturnFalse()
        {
            // Act
            var result = Wordlist.ValidateWords(null);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void ValidateWords_WithEmptyCollection_ShouldReturnTrue()
        {
            // Arrange
            var words = new string[0];

            // Act
            var result = Wordlist.ValidateWords(words);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void WordsToIndices_WithValidWords_ShouldReturnCorrectIndices()
        {
            // Arrange
            var words = new[] { "academic", "acid", "acne", "acquire" };
            var expectedIndices = new[] { 0, 1, 2, 3 };

            // Act
            var indices = Wordlist.WordsToIndices(words);

            // Assert
            Assert.Equal(expectedIndices, indices);
        }

        [Fact]
        public void WordsToIndices_WithInvalidWord_ShouldThrowArgumentException()
        {
            // Arrange
            var words = new[] { "academic", "invalidword" };

            // Act & Assert
            Assert.Throws<ArgumentException>(() => Wordlist.WordsToIndices(words));
        }

        [Fact]
        public void WordsToIndices_WithNullCollection_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => Wordlist.WordsToIndices(null));
        }

        [Fact]
        public void IndicesToWords_WithValidIndices_ShouldReturnCorrectWords()
        {
            // Arrange
            var indices = new[] { 0, 1, 2, 3 };
            var expectedWords = new[] { "academic", "acid", "acne", "acquire" };

            // Act
            var words = Wordlist.IndicesToWords(indices);

            // Assert
            Assert.Equal(expectedWords, words);
        }

        [Fact]
        public void IndicesToWords_WithInvalidIndex_ShouldThrowArgumentOutOfRangeException()
        {
            // Arrange
            var indices = new[] { 0, 1024 };

            // Act & Assert
            Assert.Throws<ArgumentOutOfRangeException>(() => Wordlist.IndicesToWords(indices));
        }

        [Fact]
        public void IndicesToWords_WithNullCollection_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => Wordlist.IndicesToWords(null));
        }

        [Fact]
        public void WordIndexRoundTrip_ShouldBeConsistent()
        {
            // Test that converting a word to index and back gives the same word
            for (int i = 0; i < 100; i++) // Test first 100 words for performance
            {
                // Arrange
                var originalWord = Wordlist.GetWord(i);

                // Act
                var index = Wordlist.GetIndex(originalWord);
                var resultWord = Wordlist.GetWord(index);

                // Assert
                Assert.Equal(i, index);
                Assert.Equal(originalWord, resultWord);
            }
        }

        [Fact]
        public void IndexWordRoundTrip_ShouldBeConsistent()
        {
            // Test that converting an index to word and back gives the same index
            var testIndices = new[] { 0, 1, 100, 500, 1022, 1023 };

            foreach (var originalIndex in testIndices)
            {
                // Arrange & Act
                var word = Wordlist.GetWord(originalIndex);
                var resultIndex = Wordlist.GetIndex(word);

                // Assert
                Assert.Equal(originalIndex, resultIndex);
            }
        }

        /// <summary>
        /// The wordlist that ships is correct by construction, so the checks that run when it is
        /// loaded never see anything wrong. These feed them the tampering they exist to catch.
        /// </summary>
        public class Verification
        {
            private static string[] Shipped() => Wordlist.Words.ToArray();

            [Fact]
            public void TheShippedWordlist_PassesEveryCheck()
            {
                Wordlist.VerifyWordlist(Shipped());
            }

            [Fact]
            public void AWordlistOfTheWrongSize_IsRejected()
            {
                var truncated = Shipped().Take(1023).ToArray();

                var ex = Assert.Throws<InvalidDataException>(() => Wordlist.VerifyWordlist(truncated));
                Assert.Contains("1023", ex.Message, StringComparison.Ordinal);
            }

            [Fact]
            public void AnUnsortedWordlist_IsRejected()
            {
                // Two real words in the wrong order. GetIndex uses a map, so nothing else would
                // notice — but sorted order is what makes the list a spec-conforming wordlist.
                var words = Shipped();
                (words[10], words[20]) = (words[20], words[10]);

                var ex = Assert.Throws<InvalidDataException>(() => Wordlist.VerifyWordlist(words));
                Assert.Contains("ascending order", ex.Message, StringComparison.Ordinal);
            }

            [Fact]
            public void ARepeatedWord_IsRejected()
            {
                // The word-to-index map used to overwrite duplicates in silence, so a list with a
                // repeated word passed the count check while GetIndex resolved to the last one.
                var words = Shipped();
                words[2] = words[1];

                Assert.Throws<InvalidDataException>(() => Wordlist.VerifyWordlist(words));
            }

            [Theory]
            [InlineData("ace")]        // shorter than 4 letters
            [InlineData("acidophile")] // longer than 8
            public void AWordOfTheWrongLength_IsRejected(string replacement)
            {
                var words = Shipped();
                words[1] = replacement;

                var ex = Assert.Throws<InvalidDataException>(() => Wordlist.VerifyWordlist(words));
                Assert.Contains("4 and 8", ex.Message, StringComparison.Ordinal);
            }

            [Fact]
            public void TwoWordsSharingAFourLetterPrefix_AreRejected()
            {
                // "acidz" sorts between "acid" and "acquire", so the list is still ordered, all
                // words are still distinct, and only the prefix rule catches it. Abbreviated
                // entry — typing the first four letters — would be ambiguous.
                var words = Shipped();
                words[2] = "acidz";

                var ex = Assert.Throws<InvalidDataException>(() => Wordlist.VerifyWordlist(words));
                Assert.Contains("first 4 characters", ex.Message, StringComparison.Ordinal);
            }

            [Fact]
            public void AWellFormedButDifferentWordlist_IsRejected()
            {
                // "zeta" sorts after "yoga" and before nothing, is 4 letters, and has a prefix no
                // other word has: it satisfies every structural rule the specification states.
                // Only the hash can tell that this is not the SLIP-0039 wordlist — which is the
                // whole point of pinning it, since a substituted list would decode every mnemonic
                // to something plausible and wrong.
                var words = Shipped();
                words[1023] = "zeta";

                var ex = Assert.Throws<InvalidDataException>(() => Wordlist.VerifyWordlist(words));
                Assert.Contains("not the SLIP-0039 wordlist", ex.Message, StringComparison.Ordinal);
            }
        }

        [Fact]
        public void Words_CannotBeCastBackToTheInternalArray()
        {
            // The property used to hand out the live array, so any code in the process could
            // rewrite how every mnemonic encodes and decodes. Assigning to it no longer
            // compiles; this covers the runtime half — the array cannot be recovered by a cast.
            var words = Wordlist.Words;

            Assert.Null(words as string[]);
            Assert.IsNotType<string[]>(words);
        }

        [Fact]
        public void Words_ShouldBeInStrictlyAscendingOrder()
        {
            // The list is sorted by construction, and the loader refuses anything else. Sorted
            // order also implies the entries are distinct.
            var words = Wordlist.Words;

            for (int i = 1; i < words.Count; i++)
            {
                Assert.True(string.CompareOrdinal(words[i - 1], words[i]) < 0,
                    $"'{words[i - 1]}' at {i - 1} is not before '{words[i]}' at {i}.");
            }
        }

        [Fact]
        public void Words_ShouldBeIdentifiedByTheirFirstFourCharacters()
        {
            // The SLIP-0039 wordlist is built so a word can be recognised — and typed — from its
            // first four letters. Anything that breaks this breaks abbreviated entry.
            var words = Wordlist.Words;

            Assert.All(words, w => Assert.InRange(w.Length, 4, 8));
            Assert.Equal(words.Count, words.Select(w => w[..4]).Distinct(StringComparer.Ordinal).Count());
        }

        [Fact]
        public void Words_ShouldHaveUniqueEntries()
        {
            // Act
            var words = Wordlist.Words;
            var uniqueWords = words.Distinct().ToArray();

            // Assert
            Assert.Equal(words.Count, uniqueWords.Length);
        }

        [Fact]
        public void Words_ShouldNotContainNullOrEmpty()
        {
            // Act
            var words = Wordlist.Words;

            // Assert
            Assert.True(words.All(w => !string.IsNullOrEmpty(w)));
        }

        [Fact]
        public void Words_ShouldBeInLowerCase()
        {
            // Act
            var words = Wordlist.Words;

            // Assert
            Assert.True(words.All(w => w == w.ToLowerInvariant()));
        }

        [Fact]
        public void KnownWords_ShouldBeAtExpectedIndices()
        {
            // Test some known words from the SLIP-0039 specification
            var knownWordsAndIndices = new[]
            {
                ("academic", 0),
                ("acid", 1),
                ("zero", 1023),
                ("satoshi", 781), // Special Bitcoin-related word
                ("trust", 941),
                ("wisdom", 1008)
            };

            foreach (var (word, expectedIndex) in knownWordsAndIndices)
            {
                // Act & Assert
                Assert.Equal(expectedIndex, Wordlist.GetIndex(word));
                Assert.Equal(word, Wordlist.GetWord(expectedIndex));
            }
        }
    }
}
