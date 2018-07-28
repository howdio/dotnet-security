using System;

namespace Howdio.Security.Encoding
{
    public abstract class Encoder
    {
        // char.IsWhiteSpace fits well but it match other whitespaces 
        // characters too and also works for unicode characters.
        public static bool IsSpace(char c)
        {
            switch (c)
            {
                case ' ':
                case '\t':
                case '\n':
                case '\v':
                case '\f':
                case '\r':
                    return true;
            }
            return false;
        }

        internal Encoder()
        {
        }

        public virtual string Encode(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            return Encode(data, 0, data.Length);
        }

        public abstract string Encode(byte[] data, int offset, int count);

        public abstract byte[] Decode(string encoded);
    }

    public static class Encoders
    {
        public static HexEncoder Hex { get; private set; }
        public static UTF8Encoder UTF8 { get; private set; }
        public static ASCIIEncoder ASCII { get; private set; }
        public static Base58Encoder Base58 { get; private set; }
        public static Base64Encoder Base64 { get; private set; }

        static Encoders()
        {
            Base64 = new Base64Encoder();
            Base58 = new Base58Encoder();
            Hex = new HexEncoder();
            UTF8 = new UTF8Encoder();
            ASCII = new ASCIIEncoder();
        }
    }
}