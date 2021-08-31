using Konscious.Security.Cryptography;
using Sobenz.Authorization.Interfaces;
using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Services
{
    internal class UserService : IUserService
    {
        private readonly List<User> _userList;

        public UserService()
        {
            byte[] salt = null;
            using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
            {
                salt = new byte[32];
                rng.GetBytes(salt);
            }

            var pwdBytes = Encoding.UTF8.GetBytes("password");
            var argon2 = new Argon2i(pwdBytes);
            argon2.DegreeOfParallelism = 1;
            argon2.MemorySize = 1024;
            argon2.Iterations = 2;
            argon2.Salt = salt;

            var hashPwdBytes = argon2.GetBytes(128);


            _userList = new List<User>
            {
                new User
                {
                    Id = Guid.Parse("e4a6d29a-1c6f-4f06-ab82-0ca69998ade2"),
                    FirstName = "Ben",
                    LastName = "Vaughan",
                    DateOfBirth = new DateTime(1976,12,17),
                    EmailAddress = "ben@sobenz.co.nz",
                    EmailVerified = true,
                    State = UserState.Active,
                    GlobalRoles = new [] { Roles.SecurityManager },
                    ContextualRoles = new Dictionary<int, IEnumerable<string>>(),
                    Identities = new List<UserIdentity>
                    {
                        new UserPasswordIdentity
                        {
                            CreatedUtc = DateTime.UtcNow,
                            Username = "ben@sobenz.co.nz",
                            Password = Convert.ToBase64String(hashPwdBytes),
                            Salt = Convert.ToBase64String(salt)
                        }
                    }
                }
            };
        }

        public Task<User> GetUserAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var user = _userList.FirstOrDefault(u => u.Id == id);
                return Task.FromResult(user);
        }

        public Task<User> GetUserByUsernameAsync(string username, CancellationToken cancellationToken = default)
        {
            User user = _userList.FirstOrDefault(u =>
            {
                var pwdIdentities = u.Identities.OfType<UserPasswordIdentity>();
                if (pwdIdentities.Any(i => i.Username.Equals(username, StringComparison.OrdinalIgnoreCase)))
                    return true;
                return false;
            });
            return Task.FromResult(user);
        }
    }
}
