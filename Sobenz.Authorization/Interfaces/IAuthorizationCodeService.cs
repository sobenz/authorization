using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Interfaces
{
    public interface IAuthorizationCodeService
    {
        Task<string> CreateAuthorizationCodeAsync(Guid clientId, Guid grantingUserId, string redirectionUri, IEnumerable<string> grantedScopes, string codeChallenge, CodeChallengeMethod? codeChallengeMethod, CancellationToken cancellationToken = default);

        Task<AuthorizationCode> ValidateCodeAsync(string authorizationCode, CancellationToken cancellationToken = default);
    }
}
