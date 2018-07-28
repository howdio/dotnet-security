using System.Linq;
using Howdio.Security.Cryptography;
using Howdio.Security.Encoding;
using Xunit;

namespace Howdio.Security.Cryptography
{
    public class HashesTest
    {
        [Theory]
        [InlineData("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
        [InlineData("The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")]
        public void Hash_SHA265(string data, string expectedResult)
        {
            Assert.Equal(expectedResult.ToByteArray(), Hashes.SHA256(Encoders.ASCII.Decode(data)));
        }

        [Theory]
        [InlineData("", "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")]
        [InlineData("The quick brown fox jumps over the lazy dog", "6d37795021e544d82b41850edf7aabab9a0ebe274e54a519840c4666f35b3937")]
        public void Hash_SHA265d(string value, string expectedResult)
        {
            Assert.Equal(expectedResult.ToByteArray(), Hashes.SHA256d(Encoders.ASCII.Decode(value)));
        }

        [Theory]
        [InlineData("", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")]
        [InlineData("The quick brown fox jumps over the lazy dog", "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15")]
        public void Hash_Keccak256(string value, string expectedResult)
        {
            Assert.Equal(expectedResult.ToByteArray(), Hashes.Keccak256(Encoders.ASCII.Decode(value)));
        }
    }
}