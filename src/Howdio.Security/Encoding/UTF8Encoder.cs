namespace Howdio.Security.Encoding
{
    public class UTF8Encoder : Encoder
    {
        public override byte[] Decode(string encoded)
        {
            return System.Text.Encoding.UTF8.GetBytes(encoded);
        }

        public override string Encode(byte[] data, int offset, int count)
        {
            return System.Text.Encoding.UTF8.GetString(data, offset, count);
        }
    }
}