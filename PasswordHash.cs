using System;
using System.Linq;
using System.Security.Cryptography;
using Klinkby.Security.Properties;

namespace Klinkby.Security
{
    // Inspired by http://stackoverflow.com/a/22208681
    public static class PasswordHash
    {
        private static readonly int Iterations = Settings.Default.Iterations; // 12500 takes ~100 mS on a 2015 i7 laptop
        const int SaltSize = 20;
        const int KeySize = 20;
        const int TotalSize = SaltSize + KeySize;

        public static string GenerateHash(string password)
        {
            if (null == password) throw new ArgumentNullException("password");
            byte[] salt = new byte[SaltSize];
            RndGen.Random.GetBytes(salt);
            byte[] key = new byte[KeySize];
            using (var hashBytes = new Rfc2898DeriveBytes(password, salt, Iterations))
            {
                key = hashBytes.GetBytes(KeySize);
            }
            byte[] ret = new byte[TotalSize];
            Buffer.BlockCopy(salt, 0, ret, 0, SaltSize);
            Buffer.BlockCopy(key, 0, ret, SaltSize, KeySize);
            // returns salt/key pair
            return Convert.ToBase64String(ret);
        }

        public static bool ComparePasswordHash(string passwordHash, string password)
        {
            if (null == passwordHash) throw new ArgumentNullException("passwordHash");
            if (null == password) throw new ArgumentNullException("password");
            byte[] hash = Convert.FromBase64String(passwordHash);
            if (TotalSize != hash.Length) return false;
            byte[] salt = new byte[SaltSize];
            byte[] key = new byte[KeySize];
            Buffer.BlockCopy(hash, 0, salt, 0, SaltSize);
            Buffer.BlockCopy(hash, SaltSize, key, 0, KeySize);
            byte[] newKey;
            using (var hashBytes = new Rfc2898DeriveBytes(password, salt, Iterations))
            {
                newKey = hashBytes.GetBytes(KeySize);
            }
            return newKey.SequenceEqual(key);
        }
    }
}
