using System;
using System.Numerics;
using Xunit;

namespace Howdio.Security
{
    public class HexConverterExtensionsTest
    {
        [Fact]
        public void Encode_WithPrefix()
        {
            var value = new byte[] { 0xFF, 0x01, 0x02 };
            var result = value.ToHexString(true);
            Assert.Equal("0xff0102", result);
        }

        [Fact]
        public void Encode_WithoutPrefix()
        {
            var value = new byte[] { 0xFF, 0x01, 0x02 };
            var result = value.ToHexString(false);
            Assert.Equal("ff0102", result);
        }

        [Fact]
        public void Decode_WithPrefix()
        {
            var value = "0xff0102";
            var result = value.ToByteArray();
            Assert.Equal(new byte[] { 0xFF, 0x01, 0x02 }, result);
        }

        [Fact]
        public void Decode_WithoutPrefix()
        {
            var value = "ff0102";
            var result = value.ToByteArray();
            Assert.Equal(new byte[] { 0xFF, 0x01, 0x02 }, result);
        }

        [Fact]
        public void Decode_BigInteger()
        {
            var value = "ff0102";
            var result = value.ToBigInteger();
            Assert.Equal(result, 16711938);
            Assert.Equal(result, new BigInteger(new byte[] { 0xFF, 0x01, 0x02 }, true, true));
        }
    }
}