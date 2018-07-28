using System.Security.Cryptography;

namespace Howdio.Security.Cryptography
{
    public static class SecureRandom
    {
        public static byte[] Next(int length)
        {
            using (var rnd = new RNGCryptoServiceProvider())
            {
                var buffer = new byte[length];
                rnd.GetBytes(buffer);
                return buffer;
            }
        }
    }
}