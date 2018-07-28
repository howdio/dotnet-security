using System.Numerics;

namespace Howdio.Security.Cryptography
{
    public interface IDSAKCalculator
    {
        void Initialize(BigInteger n, BigInteger privateKey, byte[] message);
        BigInteger GetNextK();
    }
}