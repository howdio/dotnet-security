using System;
using System.Linq;

namespace Howdio.Security
{
    public static class ArrayExtensions
    {
        public static T[] SafeSubArray<T>(this T[] me, int offset, int count)
        {
            var data = new T[count];
            Buffer.BlockCopy(me, offset, data, 0, count);
            return data;
        }

        public static T[] SafeSubArray<T>(this T[] me, int offset)
        {
            return SafeSubArray(me, offset, me.Length - offset);
        }

        public static T[] Concat<T>(this T[] me, params T[][] arrays)
        {
            var len = me.Length + arrays.Sum(x => x.Length);
            var buffer = new T[len];
            Array.Copy(me, 0, buffer, 0, me.Length);

            var pos = me.Length;
            foreach (var arr in arrays)
            {
                Array.Copy(arr, 0, buffer, pos, arr.Length);
                pos += arr.Length;
            }
            return buffer;
        }

        public static bool IsEqualTo<T>(this T[] me, T[] other)
        {
            if (ReferenceEquals(me, other)) return true;
            if (me == null ^ other == null) return false;
            return me.SequenceEqual(other);
        }
    }
}