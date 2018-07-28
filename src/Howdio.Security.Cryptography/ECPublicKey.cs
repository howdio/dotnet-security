using System.Numerics;
using Howdio.Security.Utils;

namespace Howdio.Security.Cryptography
{
    public class ECPublicKey : IBinarySerializable
    {
        private readonly byte[] _key;

        private readonly ECCurve _curve;

        public ECPublicKey(byte[] key, ECCurve curve)
        {
            _key = key;
            _curve = curve;
        }

        public ECPublicKey(ECPoint point, bool isCompressed)
            : this(point.Encode(isCompressed), point.Curve)
        { }

        internal ECPoint Point => ECPoint.Decode(_key, _curve);

        public byte[] ToByteArray()
        {
            return _key.SafeSubArray(0);
        }

        public bool Verify(byte[] messageHash, ECDSASignature signature)
        {
            var signer = new ECDSASigner(Point);
            return signer.VerifySignature(messageHash, signature.R, signature.S);
        }

        /*public static ECPublicKey Recover(ECDSASignature signature, byte[] messageHash)
		{
			return signature.Recover(messageHash);
		}*/
    }
}