using Sobenz.Authorization.Common.Models;
using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Interfaces
{
    public interface IAuthorizationManager
    {
        Task<AuthorizationOutcome<Application>> AuthenticateApplicationAsync(Guid? clientId, string clientSecret, Uri redirectionUrl, IEnumerable<string> scopes, CancellationToken cancellationToken = default);
        Task<AuthorizationOutcome<User>> AuthenticateUserAsync(string username, string password, CancellationToken cancellationToken = default);
        Task<AuthorizationOutcome> GenerateApplicationAccessTokenAsync(Application application, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken);
        Task<AuthorizationOutcome> GenerateUserAccessTokenAsync(Application application, string authroizationCode, string codeVerifier, Uri redirectUri, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken);
        Task<AuthorizationOutcome> GenerateUserAccessTokenAsync(Application application, string username, string password, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken);
        Task<AuthorizationOutcome> RefreshAccessTokenAsync(Application application, string refreshToken, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken);
    }
}
