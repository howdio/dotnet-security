using System;
using Xunit;

namespace Howdio.Security.Encoding
{
    public class HexEncoderTest
    {
        [Fact]
        public void Encode()
        {
            var encoder = Encoders.Hex;
            var value = new byte[] { 0xFF, 0x01, 0x02 };
            var result = encoder.Encode(value);
            Assert.Equal("ff0102", result);
        }

        [Fact]
        public void Encode_WithOffset()
        {
            var encoder = Encoders.Hex;
            var value = new byte[] { 0xFF, 0x01, 0x02 };
            var result = encoder.Encode(value, 1, 1);
            Assert.Equal("01", result);
        }

        [Fact]
        public void Encode_NullData()
        {
            var encoder = Encoders.Hex;
            Assert.Throws<ArgumentNullException>(() => _ = encoder.Encode(null));
        }

        [Fact]
        public void Encode_WithOffsetAndNullData()
        {
            var encoder = Encoders.Hex;
            Assert.Throws<ArgumentNullException>(() => _ = encoder.Encode(null, 0, 1));
        }

        [Fact]
        public void Decode()
        {
            var encoder = Encoders.Hex;
            var result = encoder.Decode("ff0102");
            Assert.Equal(new byte[] { 0xFF, 0x01, 0x02 }, result);
        }

        [Fact]
        public void Decode_UpperCase()
        {
            var encoder = Encoders.Hex;
            var result = encoder.Decode("FF0102");
            Assert.Equal(new byte[] { 0xFF, 0x01, 0x02 }, result);
        }

        [Fact]
        public void Decode_EmptyString()
        {
            var encoder = Encoders.Hex;
            var result = encoder.Decode("");
            Assert.Empty(result); // byte[]
        }

        [Fact]
        public void Decode_UnevenHexString()
        {
            var encoder = Encoders.Hex;
            Assert.Throws<FormatException>(() => _ = encoder.Decode("FF010"));
        }

        [Fact]
        public void Decode_InvalidHexCharacters()
        {
            var encoder = Encoders.Hex;
            Assert.Throws<FormatException>(() => _ = encoder.Decode("GG010"));
        }

        [Fact]
        public void Decode_NullData()
        {
            var encoder = Encoders.Hex;
            Assert.Throws<ArgumentNullException>(() => _ = encoder.Decode(null));
        }
    }
}