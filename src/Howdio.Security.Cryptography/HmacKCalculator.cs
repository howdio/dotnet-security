using System;
using System.Linq;
using System.Numerics;
using Howdio.Security.Utils;

namespace Howdio.Security.Cryptography
{
    public class HmacKCalculator : IDSAKCalculator
    {
        private byte[] _v;
        private byte[] _k;
        private BigInteger _n;

        public void Initialize(BigInteger n, BigInteger privateKey, byte[] messageHash)
        {
            _n = n;
            _v = Enumerable.Repeat((byte)0x01, 32).ToArray();
            _k = Enumerable.Repeat((byte)0x00, 32).ToArray();

            var prvKey = new byte[(n.GetBitLength() + 7) / 8];
            var keyBytes = privateKey.ToByteArrayUnsigned().ToBigEndian();
            Array.Copy(keyBytes, 0, prvKey, prvKey.Length - keyBytes.Length, keyBytes.Length);

            var prvMsg = new byte[(n.GetBitLength() + 7) / 8];
            var msgInt = MessageAsBigInteger(messageHash);

            if (msgInt.CompareTo(n) >= 0)
            {
                msgInt = msgInt - n;
            }
            var msgBytes = msgInt.ToByteArrayUnsigned().ToBigEndian();
            Array.Copy(msgBytes, 0, prvMsg, prvMsg.Length - msgBytes.Length, msgBytes.Length);

            _k = Hashes.HMACSHA256(_k, _v.Concat(ByteArray.Zero, prvKey, prvMsg));
            _v = Hashes.HMACSHA256(_k, _v);
            _k = Hashes.HMACSHA256(_k, _v.Concat(ByteArray.One, prvKey, prvMsg));
            _v = Hashes.HMACSHA256(_k, _v);
        }

        public BigInteger GetNextK()
        {
            do
            {
                _v = Hashes.HMACSHA256(_k, _v);
                var candidateK = _v.ToBigIntegerUnsigned(true);
                if (!candidateK.IsZero && candidateK < _n)
                {
                    return candidateK;
                }

                _k = Hashes.HMACSHA256(_k, _v.Concat(ByteArray.Zero));
                _v = Hashes.HMACSHA256(_k, _v);
            } while (true);
        }

        private BigInteger MessageAsBigInteger(byte[] message)
        {
            var v = message.ToBigIntegerUnsigned(true);
            return message.Length * 8 > _n.GetBitLength() ? v >> (message.Length * 8 - _n.GetBitLength()) : v;
        }
    }
}