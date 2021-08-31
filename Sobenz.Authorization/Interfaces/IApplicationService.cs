using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Interfaces
{
    public interface IApplicationService
    {
        Task<Application> GetAsync(Guid clientId, CancellationToken cancellationToken = default);
        Task<IEnumerable<Application>> List(CancellationToken cancellationToken = default);
    }
}
