using System;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using Howdio.Security.Encoding;
using Xunit;
using Xunit.Abstractions;

namespace Howdio.Security.Cryptography
{
    public class ECKeyTest
    {
        public const string PublicKey = "0476c7188522f82428175bd7cc6896e7ace9123b214641e6323d09f122810fdf1d6e2d94fd299a4fa0f5c262ec1747c74d330ef0ed72643443277a75c6cd937663";
        public const string PrivateKey = "866b416e9addf3e119b012e8a03bfbc916c2e57961f32354e56331be0a5400d9";
        public const string Signature = "b482b29b4381554cf90ad4d7fc37f03a18ff939d36d7af8f1da229ec363572f53c95ded0539b65ed2faeb3e59523fc2ee7d2f9fd4617fdc8a10107ede4987821";
        public static ECCurve Curve = ECCurve.Secp256k1;

        [Fact]
        public void Create_WithInvalidLength_ThrowsException()
        {
            Assert.Throws<ArgumentException>(() => new ECKey(new byte[] { 0x00 }, Curve));
        }

        [Fact]
        public void GetByteArray_AsCopy()
        {
            var bytes = PrivateKey.ToByteArray();
            var key = new ECKey(bytes, Curve);
            var result = key.ToByteArray();

            Assert.Equal(result, bytes);
            Assert.NotSame(result, bytes);
        }

        [Fact]
        public void IsCompressed_DefaultsFalse()
        {
            var key = new ECKey(PrivateKey.ToByteArray(), Curve);

            Assert.False(key.IsCompressed);
        }

        [Fact]
        public void SignMessage_Valid()
        {
            var data = PrivateKey.ToByteArray();
            var key = new ECKey(PrivateKey.ToByteArray(), Curve);
            var signature = key.Sign(PrivateKey.ToByteArray());

            var signatureHex = signature.ToByteArray().ToHexString();

            var verified = key.PublicKey.Verify(data, signature);
            Assert.True(verified);
            Assert.Equal(Signature, signatureHex);
        }



        [Fact]
        public void RecoverPublicKeyFromSignature_Valid()
        {
            var data = PrivateKey.ToByteArray();
            var key = new ECKey(PrivateKey.ToByteArray(), Curve);
            var signature = key.Sign(PrivateKey.ToByteArray());

            var keyRecovered = signature.Recover(data, 27);

            Assert.Equal(key.PublicKey.ToByteArray(), keyRecovered.ToByteArray());
        }
    }
}