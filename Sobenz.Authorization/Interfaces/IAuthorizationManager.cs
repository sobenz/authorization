using Sobenz.Authorization.Models;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Interfaces
{
    public interface IAuthorizationManager
    {
        Task<ITokenResponse> GenerateApplicationAccessTokenAsync(Application application, IEnumerable<string> scopes, int? organisationId, out HttpStatusCode statusCode, CancellationToken cancellationToken);
        Task<ITokenResponse> GenerateUserAccessTokenAsync(Application application, string username, string password, IEnumerable<string> scopes, int? organisationId, out HttpStatusCode statusCode, CancellationToken cancellationToken);
        Task<ITokenResponse> RefreshAccessTokenAsync(Application application, string refreshToken, IEnumerable<string> scopes, int? organisationId, out HttpStatusCode statusCode, CancellationToken cancellationToken);
    }
}
