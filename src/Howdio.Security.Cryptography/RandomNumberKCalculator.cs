using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using Howdio.Security.Utils;

namespace Howdio.Security.Cryptography
{
    public class RandomNumberKCalculator : IDSAKCalculator
    {
        private int _bitLength;
        private RandomNumberGenerator _random;

        public void Initialize(BigInteger n, BigInteger privateKey, byte[] messageHash)
        {
            if (_random == null)
            {
                _random = RandomNumberGenerator.Create();
            }
            _bitLength = n.GetBitLength();
        }

        public BigInteger GetNextK()
        {
            return _random.NextBigInteger(_bitLength);
        }
    }
}