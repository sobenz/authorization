using Sobenz.Authorization.Common.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Common.Interfaces
{
    public interface IApplicationStore
    {
        Task<Application> GetAsync(Guid clientId, CancellationToken cancellationToken = default);
        Task<IEnumerable<Application>> List(CancellationToken cancellationToken = default);
    }
}
