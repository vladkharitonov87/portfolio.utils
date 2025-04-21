using Portfolio.Utils.Cryptography.Encryption;

namespace Portfolio.Utils.Cryptography
{
    public static class CryptoHelper
    {
        public static string EncryptText(string data)
        {
            if (string.IsNullOrWhiteSpace(data))
                return data;

            return Encryptor.Encrypt(data);
        }

        public static string DecryptText(string data)
        {
            if (string.IsNullOrWhiteSpace(data))
                return data;

            return Encryptor.Decrypt(data);
        }
    }
}