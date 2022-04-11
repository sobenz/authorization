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
        Task<AuthorizationOutcome<Client>> AuthenticateApplicationAsync(Guid? clientId, string clientSecret, Uri redirectionUrl, IEnumerable<string> scopes, CancellationToken cancellationToken = default);
        Task<AuthorizationOutcome<User>> AuthenticateUserAsync(string username, string password, CancellationToken cancellationToken = default);
        Task<AuthorizationOutcome> GenerateApplicationAccessTokenAsync(Client client, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken);
        Task<AuthorizationOutcome> GenerateUserAccessTokenAsync(Client client, string authroizationCode, string codeVerifier, Uri redirectUri, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken);
        Task<AuthorizationOutcome> GenerateUserAccessTokenAsync(Client client, string username, string password, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken);
        Task<AuthorizationOutcome> RefreshAccessTokenAsync(Client client, string refreshToken, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken);
    }
}
