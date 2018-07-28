using System;
using System.Numerics;

namespace Howdio.Security.Cryptography
{
    public static class ECAlgorithms
    {
        public static ECPoint SumOfTwoMultiplies(ECPoint P, BigInteger k, ECPoint Q, BigInteger l)
        {
            int m = Math.Max(k.GetBitLength(), l.GetBitLength());
            ECPoint Z = P + Q;
            ECPoint R = P.Curve.Infinity;
            for (int i = m - 1; i >= 0; --i)
            {
                R = R.Twice();
                if (k.TestBit(i))
                {
                    if (l.TestBit(i))
                    {
                        R = R + Z;
                    }
                    else
                    {
                        R = R + P;
                    }
                }
                else
                {
                    if (l.TestBit(i))
                    {
                        R = R + Q;
                    }
                }
            }
            return R;
        }
    }
}