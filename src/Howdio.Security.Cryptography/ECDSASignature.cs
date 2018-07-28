using System;
using System.Linq;
using System.Numerics;
using Howdio.Security.Utils;

namespace Howdio.Security.Cryptography
{
    public class ECDSASignature
    {
        private readonly ECCurve _curve;

        public ECDSASignature(BigInteger[] rs, ECCurve curve)
            : this(rs[0], rs[1], curve)
        {
            R = rs[0];
            S = rs[1];
        }

        public ECDSASignature(BigInteger r, BigInteger s, ECCurve curve)
        {
            R = r;
            S = s;
            _curve = curve;
        }

        public BigInteger R { get; }
        public BigInteger S { get; }

        public byte[] ToByteArray()
        {
            return R.ToByteArrayUnsigned().ToBigEndian().Concat(S.ToByteArrayUnsigned().ToBigEndian());
        }

        public ECPublicKey Recover(byte[] messageHash, byte v, bool compressed = false)
        {
            if (messageHash == null)
            {
                throw new ArgumentNullException(nameof(messageHash));
            }
            var recId = CalculateRecoverId(v);
            var n = _curve.N;
            var x = R + (new BigInteger(recId / 2) * n);
            var p = _curve.Q;

            if (x.CompareTo(p) >= 0)
            {
                return null;
            }

            var dR = DecompressKey(x, (recId & 1) == 1, _curve);

            if (!ECPoint.Multiply(dR, n).IsInfinity)
            {
                return null;
            }

            var e = messageHash.ToBigIntegerUnsigned(true);
            var eInv = (BigInteger.Zero - e).Mod(n);
            var rInv = R.ModInverse(n);
            var srInv = (rInv * S).Mod(n);
            var eInvrInv = (rInv * eInv).Mod(n);
            var q = ECAlgorithms.SumOfTwoMultiplies(_curve.G, eInvrInv, dR, srInv);
            return compressed ? new ECPublicKey(new ECPoint(new ECFieldElement(q.X.Value, _curve), new ECFieldElement(q.Y.Value, _curve), _curve), true) : new ECPublicKey(q, false);
        }

        private static ECPoint DecompressKey(BigInteger xBN, bool yBit, ECCurve curve)
        {
            var compEnc = ConvertIntegerToBytes(xBN, 1 + ((curve.Q.GetBitLength() + 7) / 8));
            compEnc[0] = (byte)(yBit ? 0x03 : 0x02);
            return ECPoint.Decode(compEnc, curve);
        }

        private static int CalculateRecoverId(byte v)
        {
            var header = v;
            if ((header < 27) || (header > 34))
            {
                throw new Exception("Header byte out of range: " + header);
            }
            if (header >= 31)
            {
                header -= 4;
            }
            return header - 27;
        }

        private static byte[] ConvertIntegerToBytes(BigInteger s, int qLength)
        {
            byte[] bytes = s.ToByteArray(true);
            if (qLength != bytes.Length)
            {
                return bytes.SafeSubArray(qLength);
            }
            return bytes;
        }

        /*public byte[] ToDER()
		{
			var r = Packer.BigEndian.GetBytes(R.ToByteArray());
			var s = Packer.BigEndian.GetBytes(S.ToByteArray());
			var lenght = r.Length + s.Length + 4;

			return Packer.Pack("bbbbAbbA", 0x30, lenght, 0x02, r.Length, r, 0x02, s.Length, s);
		}

		public static ECDSASignature FromDER(byte[] sig)
		{
			if(sig.Length < 70)
            {
				throw new FormatException("Signature is not DER formatted. " + "Signature too large or too short");
            }
			if(sig[0] != 0x30)
            {
				throw new FormatException("Signature is not DER formatted. " + "Header byte should be 0x30");
            }
			if(sig[1] < 68)
            {
				throw new FormatException("Signature is not DER formatted. " + "Wrong length byte value");
            }

			if(sig[2] != 0x02)
            {
				throw new FormatException("Signature is not DER formatted. " + "Integer byte for R should be 0x02");
            }
			var rlength = sig[3];
			if(rlength != 0x20 && rlength != 0x21)
            {
				throw new FormatException("Signature is not DER formatted. " + "Length of R incorrect");
            }
			if(sig[4] >= 0x80  || (sig[4] == 0x00 && sig[5] < 0x80))
            {
				throw new FormatException("Signature is not DER formatted. " + "R is not valid");
            }

			if(sig[4 + rlength] != 0x02)
            {
				throw new FormatException("Signature is not DER formatted. " + "Integer byte for S should be 0x02");
            }

			var slength = sig[5 + rlength];
			if(slength != 0x20 && slength != 0x21)
            {
				throw new FormatException("Signature is not DER formatted. " + "Length of S incorrect");
            }
			if(sig[6 + rlength] >= 0x80 || (sig[6 + rlength] == 0x00 && sig[7 + rlength] < 0x80))
            {
				throw new FormatException("Signature is not DER formatted. " + "R is not valid");
            }

			if(rlength + slength + 4 != sig[1])
            {
				throw new FormatException("Signature is not DER formatted. " + "Lenght is incorrect");
            }

			var r = new BigInteger(sig.SafeSubArray(4, rlength).ToBigEndian());
			var s = new BigInteger(sig.SafeSubArray(4 + rlength + 2, slength).ToBigEndian());
			return new ECDSASignature(r, s);
		}

		public ECDSASignature MakeCanonical()
		{
			var isLowS = S <= HalfCurveOrder;
			return isLowS ? this : new ECDSASignature(R, Secp256k1.N - S); 
		}*/
    }
}