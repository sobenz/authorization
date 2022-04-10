using Sobenz.Authorization.Common.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Common.Interfaces
{
    public interface IClientStore
    {
        Task<Client> GetClientAsync(Guid clientId, CancellationToken cancellationToken = default);
        Task<IEnumerable<Client>> ListClientsAsync(CancellationToken cancellationToken = default);
    }
}
