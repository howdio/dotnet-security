namespace Howdio.Security.Encoding
{
    public static class CheckEncoders
    {
        public static Base58CheckEncoder Base58Check { get; private set; }

        static CheckEncoders()
        {
            Base58Check = new Base58CheckEncoder();
        }
    }
}