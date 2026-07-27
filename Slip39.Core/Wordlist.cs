using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Slip39.Core
{
    /// <summary>
    /// SLIP-0039 wordlist containing 1024 words for mnemonic generation and validation.
    /// Each word is mapped to an index from 0 to 1023.
    /// </summary>
    /// <remarks>
    /// The wordlist is the mapping between mnemonics and bits: change it and every share this
    /// process reads or writes changes meaning, silently and consistently enough to look correct.
    /// It is therefore loaded from the embedded resource only, verified on load, and exposed
    /// read-only.
    /// </remarks>
    public static class Wordlist
    {
        /// <summary>
        /// SHA-256 of the 1024 words, lowercased and joined with '\n'. Hashing the words rather
        /// than the file makes the constant independent of line endings and of the byte order
        /// mark. The list this pins is the one the official SLIP-0039 test vectors pass against.
        /// </summary>
        private const string WordlistHash = "0e3ea826bde1b1bc77e39a8d9b3682efb2c0946087d911ee6550f29bd12e87c6";

        /// <summary>
        /// The number of characters that uniquely identify a word. The SLIP-0039 wordlist is
        /// built so that a word can be recognised — and typed — from its first four letters.
        /// </summary>
        private const int UniquePrefixLength = 4;

        private static readonly Lazy<ReadOnlyCollection<string>> _words =
            new Lazy<ReadOnlyCollection<string>>(LoadWords);
        private static readonly Lazy<Dictionary<string, int>> _wordToIndex = new Lazy<Dictionary<string, int>>(CreateWordToIndexMap);

        /// <summary>
        /// Gets the 1024 words of the SLIP-0039 wordlist, in index order.
        /// </summary>
        /// <remarks>
        /// Read-only by design. This used to hand out the live internal array, so any code in the
        /// process — a helper, a test that forgot to restore state, a dependency — could rewrite
        /// how every mnemonic encodes and decodes for the lifetime of the process.
        /// </remarks>
        public static IReadOnlyList<string> Words => _words.Value;

        /// <summary>
        /// Gets the total number of words in the wordlist.
        /// </summary>
        public static int WordCount => 1024;

        /// <summary>
        /// Gets the word at the specified index.
        /// </summary>
        /// <param name="index">The index of the word (0-1023).</param>
        /// <returns>The word at the specified index.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when index is not between 0 and 1023.</exception>
        public static string GetWord(int index)
        {
            if (index < 0 || index >= WordCount)
            {
                throw new ArgumentOutOfRangeException(nameof(index),
                    $"Index must be between 0 and {WordCount - 1}.");
            }

            return Words[index];
        }

        /// <summary>
        /// Gets the index of the specified word.
        /// </summary>
        /// <param name="word">The word to find the index for.</param>
        /// <returns>The index of the word (0-1023).</returns>
        /// <exception cref="ArgumentException">Thrown when the word is not found in the wordlist.</exception>
        public static int GetIndex(string word)
        {
            if (string.IsNullOrWhiteSpace(word))
            {
                throw new ArgumentException("Word cannot be null or empty.", nameof(word));
            }

            if (_wordToIndex.Value.TryGetValue(word.ToLowerInvariant(), out int index))
            {
                return index;
            }

            throw new ArgumentException($"Word '{word}' not found in wordlist.", nameof(word));
        }

        /// <summary>
        /// Checks if the specified word exists in the wordlist.
        /// </summary>
        /// <param name="word">The word to check.</param>
        /// <returns>True if the word exists in the wordlist; otherwise, false.</returns>
        public static bool ContainsWord(string word)
        {
            if (string.IsNullOrWhiteSpace(word))
            {
                return false;
            }

            return _wordToIndex.Value.ContainsKey(word.ToLowerInvariant());
        }

        /// <summary>
        /// Validates that all words in the provided collection exist in the wordlist.
        /// </summary>
        /// <param name="words">The words to validate.</param>
        /// <returns>True if all words are valid; otherwise, false.</returns>
        public static bool ValidateWords(IEnumerable<string> words)
        {
            if (words == null)
            {
                return false;
            }

            return words.All(ContainsWord);
        }

        /// <summary>
        /// Converts a collection of words to their corresponding indices.
        /// </summary>
        /// <param name="words">The words to convert.</param>
        /// <returns>An array of indices corresponding to the words.</returns>
        /// <exception cref="ArgumentException">Thrown when any word is not found in the wordlist.</exception>
        public static int[] WordsToIndices(IEnumerable<string> words)
        {
            if (words == null)
            {
                throw new ArgumentNullException(nameof(words));
            }

            return words.Select(GetIndex).ToArray();
        }

        /// <summary>
        /// Converts a collection of indices to their corresponding words.
        /// </summary>
        /// <param name="indices">The indices to convert.</param>
        /// <returns>An array of words corresponding to the indices.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when any index is not between 0 and 1023.</exception>
        public static string[] IndicesToWords(IEnumerable<int> indices)
        {
            if (indices == null)
            {
                throw new ArgumentNullException(nameof(indices));
            }

            return indices.Select(GetWord).ToArray();
        }

        /// <summary>
        /// Loads the wordlist from the resource embedded in this assembly.
        /// </summary>
        /// <remarks>
        /// There is deliberately no filesystem fallback. Reading <c>wordlist.txt</c> from the
        /// assembly directory meant a file dropped next to the DLL became the wordlist, with
        /// nothing checking it was the right one. The resource is embedded by the project file,
        /// so its absence is a build failure, not a runtime condition worth papering over.
        /// </remarks>
        private static ReadOnlyCollection<string> LoadWords()
        {
            var assembly = typeof(Wordlist).Assembly;
            const string resourceName = "Slip39.Core.wordlist.txt";

            using var stream = assembly.GetManifestResourceStream(resourceName)
                ?? throw new InvalidOperationException(
                    $"The embedded wordlist resource '{resourceName}' is missing from assembly " +
                    $"'{assembly.GetName().Name}'. It is embedded by Slip39.Core.csproj; a build " +
                    "that does not contain it is broken.");

            var words = ReadWords(stream);
            VerifyWordlist(words);
            return new ReadOnlyCollection<string>(words);
        }

        /// <summary>
        /// Reads the wordlist format: one lowercase word per line, blank lines ignored.
        /// </summary>
        private static string[] ReadWords(Stream stream)
        {
            var wordsList = new List<string>(WordCount);
            using var reader = new StreamReader(stream);

            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                var word = line.Trim().ToLowerInvariant();
                if (word.Length > 0)
                {
                    wordsList.Add(word);
                }
            }

            return wordsList.ToArray();
        }

        /// <summary>
        /// Checks that what was loaded is the SLIP-0039 wordlist, and not merely a list of 1024
        /// strings. The structural checks come first because they name the actual problem; the
        /// hash then settles identity, which structure alone cannot establish.
        /// </summary>
        /// <remarks>
        /// The structural checks are the mechanically verifiable criteria the specification
        /// states for the wordlist: alphabetically sorted, no word shorter than 4 or longer than
        /// 8 letters, every word identified by a unique 4-letter prefix.
        /// </remarks>
        internal static void VerifyWordlist(string[] words)
        {
            if (words.Length != WordCount)
            {
                throw new InvalidDataException($"Expected {WordCount} words but found {words.Length}.");
            }

            for (int i = 0; i < words.Length; i++)
            {
                if (words[i].Length < 4 || words[i].Length > 8)
                {
                    throw new InvalidDataException(
                        $"Wordlist entry {i} ('{words[i]}') is not between 4 and 8 characters long.");
                }

                if (i > 0 && string.CompareOrdinal(words[i - 1], words[i]) >= 0)
                {
                    throw new InvalidDataException(
                        $"Wordlist is not in strictly ascending order at index {i}: " +
                        $"'{words[i - 1]}' is not before '{words[i]}'.");
                }
            }

            int distinctPrefixes = words.Select(w => w[..UniquePrefixLength]).Distinct(StringComparer.Ordinal).Count();
            if (distinctPrefixes != words.Length)
            {
                throw new InvalidDataException(
                    $"Wordlist entries are not distinguished by their first {UniquePrefixLength} characters.");
            }

            // An ordinary comparison: the wordlist and its hash are both public constants, so
            // there is no secret here for a timing side channel to leak.
            var actualHash = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', words)))).ToLowerInvariant();
            if (!string.Equals(actualHash, WordlistHash, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"The wordlist is well formed but is not the SLIP-0039 wordlist: expected " +
                    $"SHA-256 {WordlistHash}, got {actualHash}.");
            }
        }

        private static Dictionary<string, int> CreateWordToIndexMap()
        {
            var map = new Dictionary<string, int>(WordCount, StringComparer.Ordinal);
            var words = Words;

            for (int i = 0; i < words.Count; i++)
            {
                // Add, not indexer assignment: a duplicate must fail loudly rather than resolve
                // to whichever occurrence came last. VerifyWordlist rules duplicates out, so this
                // is a second lock on the same door.
                map.Add(words[i], i);
            }

            return map;
        }
    }
}
