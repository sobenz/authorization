using Konscious.Security.Cryptography;
using Sobenz.Authorization.Interfaces;
using System;
using System.Text;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Services
{
    public class Argon2PasswordHasher : IPasswordHasher
    {
        public Task<string> HashPasswordAsync(string password, string salt)
        {
            var pwdBytes = Encoding.UTF8.GetBytes(password);
            var argon2 = new Argon2i(pwdBytes);
            argon2.DegreeOfParallelism = 1;
            argon2.MemorySize = 1024;
            argon2.Iterations = 2;
            argon2.Salt = Convert.FromBase64String(salt);
            var encPwdBytes = argon2.GetBytes(128);
            string hashedPassword = Convert.ToBase64String(encPwdBytes);
            return Task.FromResult(hashedPassword);
        }
    }
}
