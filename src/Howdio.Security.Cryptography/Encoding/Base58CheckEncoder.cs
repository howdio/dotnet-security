using System;
using System.Linq;
using System.Numerics;
using Howdio.Security.Utils;
using Howdio.Security.Cryptography;

namespace Howdio.Security.Encoding
{
    public class Base58CheckEncoder : Base58Encoder
	{
		private static readonly Base58Encoder InternalEncoder = new Base58Encoder();

		public override string Encode(byte[] data, int offset, int count)
		{
			var toEncode = new byte[count + 4];
			Buffer.BlockCopy(data, offset, toEncode, 0, count);

			var hash = Hashes.SHA256d(data, offset, count);
			Buffer.BlockCopy(hash, 0, toEncode, count, 4);

			return InternalEncoder.Encode(toEncode, 0, toEncode.Length);
		}

		public override byte[] Decode(string encoded)
		{
			var vchRet = InternalEncoder.Decode(encoded);
			if (vchRet.Length < 4)
            {
				throw new FormatException("Invalid checked base 58 string");
            }

			var calculatedHash = Hashes.SHA256d(vchRet, 0, vchRet.Length - 4).SafeSubArray(0, 4);
			var expectedHash = vchRet.SafeSubArray(vchRet.Length - 4, 4);

			if (!calculatedHash.IsEqualTo(expectedHash))
            {
				throw new FormatException("Invalid hash of the base 58 string");
            }

			vchRet = vchRet.SafeSubArray(0, vchRet.Length - 4);
			return vchRet;
		}
	}
}