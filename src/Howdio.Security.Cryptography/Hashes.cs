using System.Security.Cryptography;

namespace Howdio.Security.Cryptography
{
    public static class Hashes
    {
        #region SHA256

        public static byte[] SHA256(byte[] data)
        {
            return SHA256(data, 0, data.Length);
        }

        public static byte[] SHA256(byte[] data, int count)
        {
            return SHA256(data, 0, count);
        }

        public static byte[] SHA256(byte[] data, int offset, int count)
        {
            using (var sha = new SHA256Managed())
            {
                return sha.ComputeHash(data, offset, count);
            }
        }

        #endregion

        #region SHA256d

        public static byte[] SHA256d(byte[] data)
        {
            return SHA256d(data, 0, data.Length);
        }

        public static byte[] SHA256d(byte[] data, int count)
        {
            return SHA256d(data, 0, count);
        }

        public static byte[] SHA256d(byte[] data, int offset, int count)
        {
            var h = SHA256(data, offset, count);
            return SHA256(h, 0, h.Length);
        }

        #endregion

        #region HMACSHA265

        public static byte[] HMACSHA256(byte[] key, byte[] data)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(data);
            }
        }

        #endregion

        #region Keccak256

        public static byte[] Keccak256(byte[] data)
        {
            return Keccak256(data, 0, data.Length);
        }

        public static byte[] Keccak256(byte[] data, int count)
        {
            return Keccak256(data, 0, count);
        }

        public static byte[] Keccak256(byte[] data, int offset, int count)
        {
            using (var sha = new SHA3Managed(256))
            {
                return sha.ComputeHash(data, offset, count);
            }
        }

        #endregion
    }
}