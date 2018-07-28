using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Howdio.Security.Encoding;

namespace Howdio.Security
{
    public static class HexConverterExtensions
    {
        public static string ToHexString(this byte[] value, bool prefix = false)
        {
            return (prefix ? "0x" : "") + Encoders.Hex.Encode(value);
        }

        public static byte[] ToByteArray(this string value)
        {
            if (value.StartsWith("0x"))
            {
                value = value.Substring(2);
            }
            return Encoders.Hex.Decode(value);
        }

        public static BigInteger ToBigInteger(this string value)
        {
            byte[] bytes = ToByteArray(value);
            Array.Reverse(bytes);
            Array.Resize(ref bytes, bytes.Length + 1);
            bytes[bytes.Length - 1] = 0x00;
            return new BigInteger(bytes);
        }
    }
}