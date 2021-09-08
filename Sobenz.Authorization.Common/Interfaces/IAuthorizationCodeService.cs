using Sobenz.Authorization.Abstractions.Models;
using Sobenz.Authorization.Common.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Common.Interfaces
{
    public interface IAuthorizationCodeService
    {
        Task<string> CreateAuthorizationCodeAsync(Guid clientId, Guid grantingUserId, string redirectionUri, IEnumerable<string> grantedScopes, string codeChallenge, CodeChallengeMethod? codeChallengeMethod, string nonce, CancellationToken cancellationToken = default);

        Task<AuthorizationCode> ValidateCodeAsync(string authorizationCode, CancellationToken cancellationToken = default);
    }
}
