using Sobenz.Authorization.Models;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Interfaces
{
    public interface IUserService
    {
        Task<User> GetUserAsync(Guid id, CancellationToken cancellationToken = default);
        Task<User> GetUserByUsernameAsync(string username, CancellationToken cancellationToken = default);
    }
}
