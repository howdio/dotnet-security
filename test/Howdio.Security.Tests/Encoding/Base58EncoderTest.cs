using System;
using Xunit;

namespace Howdio.Security.Encoding
{
    public class Base58EncoderTest
    {
        [Fact]
        public void Encode_Data()
        {
            var encoder = Encoders.Base58;
            var value = new byte[] { 0xFF, 0x01, 0x02 };
            var result = encoder.Encode(value);
            Assert.Equal("2Uess", result);
        }

        [Fact]
        public void Encode_DataWithOffset()
        {
            var encoder = Encoders.Base58;
            var value = new byte[] { 0xFF, 0x01, 0x02 };
            var result = encoder.Encode(value, 0, 1);
            Assert.Equal("5Q", result);
        }

        [Fact]
        public void Decode_Data()
        {
            var encoder = Encoders.Base58;
            var result = encoder.Decode("2Uess");
            Assert.Equal(new byte[] { 0xFF, 0x01, 0x02 }, result);
        }

        [Fact]
        public void Decode_Empty()
        {
            var encoder = Encoders.Base58;
            var result = encoder.Decode("");
            Assert.Empty(result); // byte[]
        }

        [Fact]
        public void Decode_UnknownBase58Characters()
        {
            var encoder = Encoders.Base58;
            Assert.Throws<FormatException>(() => _ = encoder.Decode("2Uess!"));
        }
    }
}