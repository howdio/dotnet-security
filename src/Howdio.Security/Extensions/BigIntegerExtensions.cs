using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Howdio.Security
{
    public static class BigIntegerExtensions
    {
        public static byte[] ToByteArray(this BigInteger i, bool bigEndian)
        {
            return bigEndian ? i.ToByteArray().ToBigEndian() : i.ToByteArray();
        }

        public static byte[] ToByteArrayUnsigned(this BigInteger i, bool bigEndian = false)
        {
            var bytes = i.ToByteArray();
            if (bytes[bytes.Length - 1] == 0x00)
            {
                Array.Resize(ref bytes, bytes.Length - 1);
            }
            return bigEndian ? bytes.ToBigEndian() : bytes;
        }

        public static BigInteger ToBigInteger(this byte[] bytes)
        {
            var clone = new byte[bytes.Length];
            Buffer.BlockCopy(bytes, 0, clone, 0, bytes.Length);

            return new BigInteger(clone.ToBigEndian());
        }

        public static BigInteger ToBigIntegerUnsigned(this byte[] bytes, bool bigEndian)
        {
            byte[] clone;
            if (bigEndian)
            {
                if (bytes[0] == 0x00)
                {
                    return bytes.ToBigInteger();
                }

                clone = new byte[bytes.Length + 1];
                Buffer.BlockCopy(bytes, 0, clone, 1, bytes.Length);
                return new BigInteger(clone.ToBigEndian());
            }

            if (bytes[bytes.Length - 1] == 0x00)
            {
                return new BigInteger(bytes);
            }

            clone = new byte[bytes.Length + 1];
            Buffer.BlockCopy(bytes, 0, clone, 0, bytes.Length);
            return new BigInteger(clone);
        }

        public static byte[] ToBigEndian(this byte[] bytes)
        {
            Array.Reverse(bytes, 0, bytes.Length);
            return bytes;
        }

        public static bool TestBit(this BigInteger i, int index)
        {
            return (i & (BigInteger.One << index)) > BigInteger.Zero;
        }

        public static int GetLowestSetBit(this BigInteger i)
        {
            if (i.Sign == 0)
            {
                return -1;
            }
            byte[] b = i.ToByteArray();
            int w = 0;
            while (b[w] == 0)
            {
                w++;
            }
            for (int x = 0; x < 8; x++)
            {
                if ((b[w] & 1 << x) > 0)
                {
                    return x + w * 8;
                }
            }
            throw new Exception();
        }

        public static BigInteger Mod(this BigInteger x, BigInteger y)
        {
            x %= y;
            if (x.Sign < 0)
            {
                x += y;
            }
            return x;
        }

        public static BigInteger ModInverse(this BigInteger n, BigInteger p)
        {
            BigInteger x = 1;
            BigInteger y = 0;
            BigInteger a = p;
            BigInteger b = n;

            while (b != 0)
            {
                BigInteger t = b;
                BigInteger q = BigInteger.Divide(a, t);
                b = a - q * t;
                a = t;
                t = x;
                x = y - q * t;
                y = t;
            }

            return y < 0 ? y + p : y;
        }

        public static int GetBitLength(this BigInteger n)
        {
            int bitLength = 0;
            do
            {
                bitLength++;
                n /= 2;
            } while (n != 0);
            return bitLength;
        }

        private static BigInteger FindS(BigInteger p)
        {
            var s = p - 1;
            while (s.IsEven) s /= 2;
            return s;
        }

        private static int FindE(BigInteger p)
        {
            var s = p - 1;
            var e = 0;

            while (s.IsEven)
            {
                s >>= 2;
                e++;
            }

            return e;
        }

        private static BigInteger TwoExp(int e)
        {
            return BigInteger.One << e;
        }

        public static BigInteger NextBigInteger(this Random rand, int sizeInBits)
        {
            if (sizeInBits < 0)
            {
                throw new ArgumentException("sizeInBits must be non-negative");
            }
            if (sizeInBits == 0)
            {
                return 0;
            }
            byte[] b = new byte[sizeInBits / 8 + 1];
            rand.NextBytes(b);
            if (sizeInBits % 8 == 0)
            {
                b[b.Length - 1] = 0;
            }
            else
            {
                b[b.Length - 1] &= (byte)((1 << sizeInBits % 8) - 1);
            }
            return new BigInteger(b);
        }

        public static BigInteger NextBigInteger(this RandomNumberGenerator rng, int sizeInBits)
        {
            if (sizeInBits < 0)
            {
                throw new ArgumentException("sizeInBits must be non-negative");
            }
            if (sizeInBits == 0)
            {
                return 0;
            }
            byte[] b = new byte[sizeInBits / 8 + 1];
            rng.GetBytes(b);
            if (sizeInBits % 8 == 0)
            {
                b[b.Length - 1] = 0;
            }
            else
            {
                b[b.Length - 1] &= (byte)((1 << sizeInBits % 8) - 1);
            }
            return new BigInteger(b);
        }
    }
}