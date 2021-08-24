using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Interfaces
{
    public interface IRefreshTokenService
    {
        Task<RefreshTokenIdentifier> CreateTokenAsync(SubjectType subjectType, Guid subject, Guid? clientId, IEnumerable<string> grantedScopes, int? organisationContext = null, CancellationToken cancellationToken = default);

        Task<RefreshTokenIdentifier> RefreshTokenAsync(string token, Guid? clientId, IEnumerable<string> requestedScopes, int? organisationContext, CancellationToken cancellationToken = default);
    }
}
