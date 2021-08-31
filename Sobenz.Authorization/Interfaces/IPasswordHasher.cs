using System;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Interfaces
{
    public interface IPasswordHasher
    {
        Task<string> HashPasswordAsync(string password, string salt);
    }
}
