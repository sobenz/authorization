using Sobenz.Authorization.Models;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Interfaces
{
    public interface IUserService
    {
        Task<User> AuthenticateWithPasswordAsync(string username, string password, CancellationToken cancellationToken = default);
        Task<User> GetUserAsync(Guid id, bool includeDeactivated = false, CancellationToken cancellationToken = default);
    }
}
