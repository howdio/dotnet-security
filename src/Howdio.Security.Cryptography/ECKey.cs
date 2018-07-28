using System;
using System.Numerics;
using System.Security.Cryptography;
using Howdio.Security.Encoding;
using Howdio.Security.Utils;

namespace Howdio.Security.Cryptography
{
    public class ECKey : IBinarySerializable
    {

        private byte[] _key;
        private ECPublicKey _publicKey;
        private readonly ECCurve _curve;

        public ECKey(byte[] key, ECCurve curve)
            : this(key, curve, false)
        { }

        public ECKey(byte[] key, ECCurve curve, bool compressed)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            if (curve == null)
            {
                throw new ArgumentNullException(nameof(curve));
            }
            CheckValidKey(key, curve);

            _key = key;
            _curve = curve;
            IsCompressed = compressed;
        }

        public int KeySize => _key.Length;
        public bool IsCompressed { get; }
        public ECPublicKey PublicKey => _publicKey ?? (_publicKey = new ECPublicKey(PublicPoint, IsCompressed));

        internal ECPoint PublicPoint => _curve.G * _key;

        public byte[] ToByteArray()
        {
            return _key.SafeSubArray(0);
        }

        public ECDSASignature Sign(byte[] messageHash)
        {
            var signer = new ECDSASigner(this._key, _curve);
            return new ECDSASignature(signer.GenerateSignature(messageHash), _curve);
        }

        internal static void CheckValidKey(byte[] key, ECCurve curve)
        {
            var keySize = GetKeySize(curve);
            if (key.Length != keySize)
            {
                throw new ArgumentException($"Private key must be a {keySize} bytes length array", nameof(key));
            }
            var candidateKey = key.ToBigIntegerUnsigned(false);
            if (candidateKey <= 0 || candidateKey >= curve.N)
            {
                throw new ArgumentException("Invalid key", nameof(key));
            }
        }

        public static ECKey Create(ECCurve curve, bool compressed = false)
        {
            var rnd = SecureRandom.Next(GetKeySize(curve));
            var key = Hashes.SHA256(rnd);
            return new ECKey(key, curve, compressed);
        }

        private static int GetKeySize(ECCurve curve)
        {
            return (curve.N.GetBitLength() + 7) / 8;
        }
    }
}