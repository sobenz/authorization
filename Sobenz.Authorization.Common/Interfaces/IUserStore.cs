using Sobenz.Authorization.Common.Models;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Common.Interfaces
{
    public interface IUserStore
    {
        Task<User> GetUserAsync(Guid id, CancellationToken cancellationToken = default);
        Task<User> GetUserByUsernameAsync(string username, CancellationToken cancellationToken = default);
    }
}
