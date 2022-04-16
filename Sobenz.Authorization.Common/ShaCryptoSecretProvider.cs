using Sobenz.Authorization.Common.Interfaces;
using System;
using System.Security.Cryptography;

namespace Sobenz.Authorization.Common
{
    internal class ShaCryptoSecretProvider : IClientSecretProvider
    {
        private static readonly SHA512 _hasher = SHA512.Create();
        private static readonly RandomNumberGenerator _random = RandomNumberGenerator.Create();

        public string Generate(out string hash)
        {
            byte[] secretBytes = new byte[128];
            _random.GetNonZeroBytes(secretBytes);
            hash = Convert.ToBase64String(_hasher.ComputeHash(secretBytes));
            return Convert.ToBase64String(secretBytes);
        }

        public bool Validate(string secret, string hash)
        {
            if (string.IsNullOrWhiteSpace(hash))
                throw new ArgumentNullException(nameof(hash));

            if (string.IsNullOrWhiteSpace(secret))
                return false;

            try
            {
                byte[] secretBytes = Convert.FromBase64String(secret);
                byte[] hashedSecret = _hasher.ComputeHash(secretBytes);
                return string.Equals(hash, Convert.ToBase64String(hashedSecret), StringComparison.Ordinal);
            }
            catch
            {
                //Non base 64 encoded secret provided.
                return false;
            }
        }
    }
}
