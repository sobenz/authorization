using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Interfaces
{
    public interface IAuthorizationManager
    {
        Task<ITokenResponse> GenerateApplicationAccessToken(Application application, IEnumerable<string> scopes, int? organisationId, out HttpStatusCode statusCode, CancellationToken cancellationToken);
    }
}
