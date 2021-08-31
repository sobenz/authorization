﻿using Microsoft.Extensions.Options;
using SimpleBase;
using Sobenz.Authorization.Interfaces;
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
        private readonly List<RefreshToken> _refreshTokens = new List<RefreshToken>();
        private readonly List<AuthorizationCode> _authorizationCodes = new List<AuthorizationCode>();

        private readonly IOptions<PersistedTokenOptions> _persistedTokenOptions;

        public PersistedTokenService(IOptions<PersistedTokenOptions> persistedTokenOptions)
        {
            _persistedTokenOptions = persistedTokenOptions ?? throw new ArgumentNullException(nameof(persistedTokenOptions));
        }

        public Task<string> CreateAuthorizationCodeAsync(Guid clientId, Guid grantingUserId, string redirectionUri, IEnumerable<string> grantedScopes, string codeChallenge, CodeChallengeMethod? codeChallengeMethod, string nonce, CancellationToken cancellationToken = default)
        {
            var authorizationCode = new AuthorizationCode
            {
                Code = GenerateNewToken(),
                ClientId = clientId,
                GrantingUserId = grantingUserId,
                RedirectionUri = redirectionUri,
                GrantedScopes = grantedScopes ?? new string[0],
                ExpiresUtc = DateTime.Now.Add(_persistedTokenOptions.Value.AuthorizationCodeLifetime),
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = codeChallengeMethod,
                Nonce = nonce
            };
            _authorizationCodes.Add(authorizationCode);
            return Task.FromResult(authorizationCode.Code);
        }

        public Task<RefreshTokenIdentifier> CreateTokenAsync(SubjectType subjectType, Guid subject, Guid? clientId, IEnumerable<string> grantedScopes, int? organisationContext = null, CancellationToken cancellationToken = default)
        {
            string token = GenerateNewToken();

            var refreshToken = new RefreshToken
            {
                Token = token,
                SubjectType = subjectType,
                Subject = subject,
                ClientId = clientId,
                Scopes = new List<string>(grantedScopes ?? new string[0]),
                LastUsedOrganisationContext = organisationContext,
                ExpiresUtc = DateTime.UtcNow.Add(_persistedTokenOptions.Value.RefreshTokenLifetime),
                SessionId = Guid.NewGuid()
            };
            _refreshTokens.Add(refreshToken);

            return Task.FromResult<RefreshTokenIdentifier>(refreshToken);
        }

        public Task<RefreshTokenIdentifier> RefreshTokenAsync(string token, Guid? clientId, IEnumerable<string> requestedScopes, int? organisationContext, CancellationToken cancellationToken = default)
        {
            var refreshToken = _refreshTokens.FirstOrDefault(t => t.Token.Equals(token, StringComparison.OrdinalIgnoreCase));
            if (refreshToken?.ExpiresUtc <= DateTime.UtcNow)
                _refreshTokens.Remove(refreshToken);

            if ((refreshToken != null) && (refreshToken.ExpiresUtc > DateTime.UtcNow) && (!clientId.HasValue || (clientId == refreshToken.ClientId)))
            {
                if (requestedScopes.All(scope => refreshToken.Scopes.Contains(scope, StringComparer.OrdinalIgnoreCase)))
                {
                    if (refreshToken.SubjectType == SubjectType.User)
                    {
                        refreshToken.Token = GenerateNewToken();
                    }
                    //if(!forceRefresh) Update expiration time.
                    refreshToken.ExpiresUtc = DateTime.UtcNow.Add(_persistedTokenOptions.Value.RefreshTokenLifetime);

                    //Generate a new session if outside 2x refresh window.
                    if (refreshToken.LastRefreshUtc.HasValue && (DateTime.UtcNow.Subtract(refreshToken.LastRefreshUtc.Value) > _persistedTokenOptions.Value.UserSessionLifetime))
                    {
                        refreshToken.SessionId = Guid.NewGuid();
                    }
                    refreshToken.LastRefreshUtc = DateTime.UtcNow;
                    //Save Refresh Token Now
                    return Task.FromResult<RefreshTokenIdentifier>(refreshToken);
                }
            }
            return Task.FromResult<RefreshTokenIdentifier>(null);
        }

        public Task<AuthorizationCode> ValidateCodeAsync(string authorizationCode, CancellationToken cancellationToken = default)
        {
            var codeEntity = _authorizationCodes.FirstOrDefault(t => t.Code.Equals(authorizationCode, StringComparison.OrdinalIgnoreCase));
            if (codeEntity != null)
            {
                //Always Remove on Retrieval -- Single Use
                _authorizationCodes.Remove(codeEntity);
                if (codeEntity.ExpiresUtc > DateTime.UtcNow)
                    return Task.FromResult(codeEntity);
            }
            return Task.FromResult<AuthorizationCode>(null);
        }

        private string GenerateNewToken()
        {
            
            using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
            {
                var data = new byte[32];
                rng.GetBytes(data);
                return Base58.Ripple.Encode(data);
            }
        }
    }
}
