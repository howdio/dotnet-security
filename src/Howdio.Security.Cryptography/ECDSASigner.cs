using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using Howdio.Security.Encoding;

namespace Howdio.Security.Cryptography
{
    public class ECDSASigner
    {
        private readonly byte[] _privateKey;
        private readonly ECCurve _curve;
        private readonly ECPoint _publicKey;
        private readonly IDSAKCalculator _calculator;

        public ECDSASigner(byte[] privateKey, ECCurve curve)
            : this(privateKey, curve, new HmacKCalculator())
        {
            _privateKey = privateKey;
        }

        public ECDSASigner(byte[] privateKey, ECCurve curve, IDSAKCalculator calculator)
            : this(curve.G * privateKey)
        {
            _privateKey = privateKey;
            _calculator = calculator;
        }

        public ECDSASigner(ECPoint publicKey)
        {
            _publicKey = publicKey;
            _curve = publicKey.Curve;
        }

        private BigInteger CalculateE(BigInteger n, byte[] message)
        {
            int messageBitLength = message.Length * 8;
            BigInteger trunc = new BigInteger(message.Reverse().Concat(new byte[1]).ToArray());
            if (n.GetBitLength() < messageBitLength)
            {
                trunc >>= messageBitLength - n.GetBitLength();
            }
            return trunc;
        }

        public BigInteger[] GenerateSignature(byte[] messageHash)
        {
            if (_privateKey == null)
            {
                throw new InvalidOperationException("You can only generate a signature using the private key.");
            }
            BigInteger e = CalculateE(_curve.N, messageHash);
            BigInteger d = new BigInteger(_privateKey.Reverse().Concat(new byte[1]).ToArray());
            BigInteger r, s;

            _calculator.Initialize(_curve.N, d, messageHash);

            do
            {
                BigInteger k;
                do
                {
                    do
                    {
                        k = _calculator.GetNextK();
                    }
                    while (k.Sign == 0 || k.CompareTo(_curve.N) >= 0);
                    ECPoint p = ECPoint.Multiply(_curve.G, k);
                    BigInteger x = p.X.Value;
                    r = x.Mod(_curve.N);
                }
                while (r.Sign == 0);
                s = (k.ModInverse(_curve.N) * (e + d * r)).Mod(_curve.N);
                if (s > _curve.N / 2)
                {
                    s = _curve.N - s;
                }
            }
            while (s.Sign == 0);
            return new BigInteger[] { r, s };
        }

        public bool VerifySignature(byte[] message, BigInteger r, BigInteger s)
        {
            if (r.Sign < 1 || s.Sign < 1 || r.CompareTo(_curve.N) >= 0 || s.CompareTo(_curve.N) >= 0)
            {
                return false;
            }
            BigInteger e = CalculateE(_curve.N, message);
            BigInteger c = s.ModInverse(_curve.N);
            BigInteger u1 = (e * c).Mod(_curve.N);
            BigInteger u2 = (r * c).Mod(_curve.N);
            ECPoint point = ECAlgorithms.SumOfTwoMultiplies(_curve.G, u1, _publicKey, u2);
            BigInteger v = point.X.Value.Mod(_curve.N);
            return v.Equals(r);
        }
    }
}
