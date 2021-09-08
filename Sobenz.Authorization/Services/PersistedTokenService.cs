using Microsoft.Extensions.Options;
using SimpleBase;
using Sobenz.Authorization.Abstractions.Models;
using Sobenz.Authorization.Common.Interfaces;
using Sobenz.Authorization.Common.Models;
using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Services
{
    internal class PersistedTokenService : IRefreshTokenService, IAuthorizationCodeService
    {
        private readonly IOptions<PersistedTokenOptions> _persistedTokenOptions;
        private readonly ITokenStore _tokenStore;

        public PersistedTokenService(IOptions<PersistedTokenOptions> persistedTokenOptions, ITokenStore tokenStore)
        {
            _persistedTokenOptions = persistedTokenOptions ?? throw new ArgumentNullException(nameof(persistedTokenOptions));
            _tokenStore = tokenStore ?? throw new ArgumentNullException(nameof(tokenStore));
        }

        public async Task<string> CreateAuthorizationCodeAsync(Guid clientId, Guid grantingUserId, string redirectionUri, IEnumerable<string> grantedScopes, string codeChallenge, CodeChallengeMethod? codeChallengeMethod, string nonce, CancellationToken cancellationToken = default)
        {
            var authorizationCode = new AuthorizationCode
            {
                Code = GenerateNewToken(),
                ClientId = clientId,
                GrantingUserId = grantingUserId,
                RedirectionUri = redirectionUri,
                GrantedScopes = grantedScopes ?? Array.Empty<string>(),
                ExpiresUtc = DateTime.Now.Add(_persistedTokenOptions.Value.AuthorizationCodeLifetime),
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = codeChallengeMethod,
                Nonce = nonce
            };
            await _tokenStore.UpsertTokenAsync(authorizationCode.Code, authorizationCode, _persistedTokenOptions.Value.AuthorizationCodeLifetime, cancellationToken);
            return authorizationCode.Code;
        }

        public async Task<RefreshTokenIdentifier> CreateTokenAsync(SubjectType subjectType, Guid subject, Guid? clientId, IEnumerable<string> grantedScopes, int? organisationContext = null, CancellationToken cancellationToken = default)
        {
            string token = GenerateNewToken();

            var refreshToken = new RefreshToken
            {
                Token = token,
                SubjectType = subjectType,
                Subject = subject,
                ClientId = clientId,
                Scopes = new List<string>(grantedScopes ?? Array.Empty<string>()),
                LastUsedOrganisationContext = organisationContext,
                ExpiresUtc = DateTime.UtcNow.Add(_persistedTokenOptions.Value.RefreshTokenLifetime),
                SessionId = Guid.NewGuid()
            };
            await _tokenStore.UpsertTokenAsync(refreshToken.Token, refreshToken, _persistedTokenOptions.Value.RefreshTokenLifetime, cancellationToken);
            return refreshToken;
        }

        public async Task<RefreshTokenIdentifier> RefreshTokenAsync(string token, Guid? clientId, IEnumerable<string> requestedScopes, int? organisationContext, CancellationToken cancellationToken = default)
        {
            var refreshToken = await _tokenStore.GetTokenAsync<RefreshToken>(token, cancellationToken);

            if ((refreshToken != null) && (refreshToken.ExpiresUtc > DateTime.UtcNow) && (!clientId.HasValue || (clientId == refreshToken.ClientId)))
            {
                if ((requestedScopes == null) || requestedScopes.All(scope => refreshToken.Scopes.Contains(scope, StringComparer.OrdinalIgnoreCase)))
                {
                    if (refreshToken.SubjectType == SubjectType.User)
                    {
                        refreshToken.Token = GenerateNewToken();
                    }
                    if(_persistedTokenOptions.Value.SlidingTokens) //Update expiration time.
                        refreshToken.ExpiresUtc = DateTime.UtcNow.Add(_persistedTokenOptions.Value.RefreshTokenLifetime);

                    //Generate a new session if outside session window.
                    if (refreshToken.LastRefreshUtc.HasValue && (DateTime.UtcNow.Subtract(refreshToken.LastRefreshUtc.Value) > _persistedTokenOptions.Value.UserSessionLifetime))
                    {
                        refreshToken.SessionId = Guid.NewGuid();
                    }
                    refreshToken.LastRefreshUtc = DateTime.UtcNow;

                    if ((refreshToken.SubjectType == SubjectType.User) && _persistedTokenOptions.Value.RotateUserRefreshTokens)
                    {
                        refreshToken.Token = GenerateNewToken();
                        await _tokenStore.DeleteTokenAsync<RefreshToken>(token, cancellationToken);
                    }

                    await _tokenStore.UpsertTokenAsync(refreshToken.Token, refreshToken, _persistedTokenOptions.Value.RefreshTokenLifetime, cancellationToken);
                    return refreshToken;
                }
            }
            return null;
        }

        public async Task<AuthorizationCode> ValidateCodeAsync(string authorizationCode, CancellationToken cancellationToken = default)
        {
            var codeEntity = await _tokenStore.GetTokenAsync<AuthorizationCode>(authorizationCode, cancellationToken);
            if (codeEntity != null)
            {
                //Always Remove on Retrieval -- Single Use
                await _tokenStore.DeleteTokenAsync<AuthorizationCode>(authorizationCode, cancellationToken);
                if (codeEntity.ExpiresUtc > DateTime.UtcNow)
                    return codeEntity;
            }
            return null;
        }

        private static string GenerateNewToken()
        {

            using RandomNumberGenerator rng = new RNGCryptoServiceProvider();
            var data = new byte[32];
            rng.GetBytes(data);
            return Base58.Ripple.Encode(data);
        }
    }
}
