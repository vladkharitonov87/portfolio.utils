using System.Security.Cryptography;
using System.Text;

namespace Portfolio.Utils.Cryptography.Encryption
{
    public static class Encryptor
    {
        public static string EncryptionKey = "";

        internal const int keySize = 128;

        internal const int initializationVectorSize = 16;

        public static string Encrypt(string textToDecrypt)
        {
            return Encrypt(Encoding.UTF8.GetBytes(textToDecrypt));
        }

        public static string Decrypt(string encryptedText)
        {
            return Decrypt(Convert.FromBase64String(encryptedText));
        }

        private static string Encrypt(byte[] plaintext)
        {
            // Generate a random IV
            var iv = GenerateRandomBytes(initializationVectorSize);

            // Encrypt the plaintext
            var ciphertext = Encrypt(plaintext, iv);

            // Encode the ciphertext
            return Convert.ToBase64String(ciphertext);
        }

        private static byte[] Encrypt(byte[] plaintext, byte[] iv)
        {
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));

            if (iv == null)
                throw new ArgumentNullException(nameof(iv));

            if (iv.Length != initializationVectorSize)
                throw new ArgumentOutOfRangeException(nameof(iv), "AES requires an Initialization Vector of 128-bits.");

            using var ms = new MemoryStream();
            // Insert IV at beginning of ciphertext
            ms.Write(iv, 0, iv.Length);

            var encryptor = CreateAndInitializeEncEngine().CreateDecryptor(GenerateKey(), iv);

            // Create a CryptoStream to encrypt the plaintext
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                // Encrypt the plaintext
                cs.Write(plaintext, 0, plaintext.Length);
                cs.FlushFinalBlock();
            }

            var ciphertext = ms.ToArray();

            // IV + Cipher
            return ciphertext;
        }

        public static string Decrypt(byte[] ciphertext)
        {
            using var ms = new MemoryStream(ciphertext);
            // Extract the IV from the ciphertext
            var iv = new byte[initializationVectorSize];
            var bytesToRead = initializationVectorSize;
            var bytesRead = 0;

            for (var bytes = 1; bytesToRead > 0 && bytes != 0; bytesRead += bytes, bytesToRead -= bytes)
                bytes = ms.Read(iv, bytesRead, bytesToRead);

            var decryptor = CreateAndInitializeEncEngine().CreateDecryptor(GenerateKey(), iv);

            // Create a CryptoStream to decrypt the ciphertext
            using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            // Decrypt the ciphertext
            using var sr = new StreamReader(cs, Encoding.UTF8);
            return sr.ReadToEnd();
        }

        private static Aes CreateAndInitializeEncEngine()
        {
            var encEngine = Aes.Create();

            encEngine.Mode = CipherMode.CBC;

            return encEngine;
        }

        private static byte[] GenerateRandomBytes(int size)
        {
            var bytes = new byte[size];
            RandomNumberGenerator.Create().GetBytes(bytes);

            return bytes;
        }

        private static byte[] GenerateKey()
        {
            const int hashIterations = 10000;

            // Create a salt to help prevent rainbow table attacks
            var salt = Hash.Pbkdf2(EncryptionKey, Hash.Sha512(EncryptionKey + EncryptionKey.Length.ToString()), hashIterations);

            // Generate a key from the password and salt
            return Hash.Pbkdf2(EncryptionKey, salt, hashIterations, keySize / 8);
        }
    }
}
