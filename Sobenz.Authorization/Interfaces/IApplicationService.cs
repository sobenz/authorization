using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Interfaces
{
    public interface IApplicationService
    {
        Task<Application> AuthenticateAsync(Guid clientId, CancellationToken cancellationToken = default);
        Task<Application> AuthenticateAsync(Guid clientId, string clientSecret, CancellationToken cancellationToken = default);
    }
}
