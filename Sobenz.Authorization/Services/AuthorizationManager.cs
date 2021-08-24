using Microsoft.IdentityModel.Tokens;
using Sobenz.Authorization.Interfaces;
using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Services
{
    internal class AuthorizationManager : IAuthorizationManager
    {
        private readonly JwtSecurityTokenHandler _tokenHandler;
        private readonly SigningCredentials _signingCredentials;
        private readonly IRefreshTokenService _refreshTokenService;
        private readonly IUserService _userService;

        public AuthorizationManager(IRefreshTokenService refreshTokenService, IUserService userService)
        {
            //Should be an X509 Cert
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("Password12345678"));
            _signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
            _tokenHandler = new JwtSecurityTokenHandler();
            _refreshTokenService = refreshTokenService ?? throw new ArgumentNullException(nameof(refreshTokenService));
            _userService = userService ?? throw new ArgumentNullException(nameof(userService));
        }

        public Task<ITokenResponse> GenerateApplicationAccessTokenAsync(Application application, IEnumerable<string> scopes, int? organisationId, out HttpStatusCode statusCode, CancellationToken cancellationToken)
        {
            if (!application.IsConfidential)
            {
                //Can't create access tokens for public clients.
                statusCode = HttpStatusCode.BadRequest;
                var response = new TokenResponseError { Error = TokenFailureError.InvalidClient, ErrorDescription = "Public clients not allowed." };
                return Task.FromResult<ITokenResponse>(response);
            }
            if (!application.AllowedScopes.Contains(Scopes.Merchant))
            {
                //This operation should only proceed if the request is asking for a merchant scope.
                statusCode = HttpStatusCode.Forbidden;
                var response = new TokenResponseError { Error = TokenFailureError.UnauthorizedClient, ErrorDescription = "Client has not been granted correct scopes" };
                return Task.FromResult<ITokenResponse>(response);
            }
            if (scopes.Any(s => !application.AllowedScopes.Contains(s)))
            {
                statusCode = HttpStatusCode.BadRequest;
                var response = new TokenResponseError { Error = TokenFailureError.InvalidScope, ErrorDescription = "Client does not have all requested scopes." };
                return Task.FromResult<ITokenResponse>(response);
            }

            var refreshToken = _refreshTokenService.CreateTokenAsync(SubjectType.Application, application.ClientId, null, scopes, organisationId, cancellationToken).Result;
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, application.ClientId.ToString()),
                new Claim(JwtRegisteredClaimNames.Actort, "Application"),
                new Claim("session_id", refreshToken.SessionId.ToString())
            };
            if (organisationId.HasValue)
                claims.Add(new Claim("organisation_id", $"{organisationId}"));

            var roles = (organisationId.HasValue && application.ContextualRoles.ContainsKey(organisationId.Value)) 
                ? application.GlobalRoles.Union(application.ContextualRoles[organisationId.Value])
                : application.GlobalRoles;
            foreach (var role in roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            var accessToken = _tokenHandler.CreateEncodedJwt("sobenz.com", "https://api.sobenz.com/merchant", new ClaimsIdentity(claims), DateTime.UtcNow.AddMinutes(-5), DateTime.Now.AddMinutes(5), DateTime.UtcNow, _signingCredentials);
            
            statusCode = HttpStatusCode.OK;
            var successResponse = new TokenResponseSuccess
            {
                AccessToken = accessToken,
                TokenType = TokenResponseType.AccessToken,
                ExpiresIn = (int)TimeSpan.FromMinutes(5).TotalSeconds,
                RefreshToken = refreshToken.Token
            };
            return Task.FromResult<ITokenResponse>(successResponse);
        }

        public Task<ITokenResponse> GenerateUserAccessTokenAsync(Application application, string username, string password, IEnumerable<string> scopes, int? organisationId, out HttpStatusCode statusCode, CancellationToken cancellationToken)
        {
            if (!application.IsConfidential)
            {
                //Can't create access tokens for public clients.
                statusCode = HttpStatusCode.BadRequest;
                var response = new TokenResponseError { Error = TokenFailureError.InvalidClient, ErrorDescription = "Public clients not allowed with the Password grant." };
                return Task.FromResult<ITokenResponse>(response);
            }
            
            var user = _userService.AuthenticateWithPasswordAsync(username, password, cancellationToken).Result;
            if (user == null)
            {
                statusCode = HttpStatusCode.Unauthorized;
                var response = new TokenResponseError { Error = TokenFailureError.AccessDenied, ErrorDescription = "Authentication Failed." };
                return Task.FromResult<ITokenResponse>(response);
            }

            var refreshToken = _refreshTokenService.CreateTokenAsync(SubjectType.User, user.Id, application.ClientId, scopes, organisationId, cancellationToken).Result;

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Actort, "User"),
                new Claim("client_id", application.ClientId.ToString()),
                new Claim("session_id", refreshToken.SessionId.ToString())
            };
            if (organisationId.HasValue)
                claims.Add(new Claim("organisation_id", $"{organisationId}"));

            //If they are a merchant we add any roles they may have associated.
            string audience = "https://api.sobenz.com/consumer";
            if (scopes.Contains(Scopes.Merchant))
            {
                audience = "https://api.sobenz.com/merchant";
                var roles = (organisationId.HasValue && user.ContextualRoles.ContainsKey(organisationId.Value))
                    ? user.GlobalRoles.Union(user.ContextualRoles[organisationId.Value])
                    : user.GlobalRoles;
                foreach (var role in roles)
                    claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var accessToken = _tokenHandler.CreateEncodedJwt("sobenz.com", audience, new ClaimsIdentity(claims), DateTime.UtcNow.AddMinutes(-5), DateTime.Now.AddMinutes(5), DateTime.UtcNow, _signingCredentials);

            statusCode = HttpStatusCode.OK;
            var successResponse = new TokenResponseSuccess
            {
                AccessToken = accessToken,
                TokenType = TokenResponseType.AccessToken,
                ExpiresIn = (int)TimeSpan.FromMinutes(5).TotalSeconds,
                RefreshToken = refreshToken.Token
            };
            return Task.FromResult<ITokenResponse>(successResponse);
        }

        public Task<ITokenResponse> RefreshAccessTokenAsync(Application application, string token, IEnumerable<string> scopes, int? organisationId, out HttpStatusCode statusCode, CancellationToken cancellationToken)
        {
            var refreshToken = _refreshTokenService.RefreshTokenAsync(token, application.ClientId, scopes, organisationId, cancellationToken).Result;
            if (token == null)
            {
                statusCode = HttpStatusCode.Unauthorized;
                var response = new TokenResponseError { Error = TokenFailureError.AccessDenied, ErrorDescription = "Authentication Failed." };
                return Task.FromResult<ITokenResponse>(response);
            }

            //TODO Make User and Application Common
            User user = null;
            if (refreshToken.SubjectType == SubjectType.User)
            {
                user = _userService.GetUserAsync(refreshToken.Subject, includeDeactivated: false, cancellationToken).Result;
            }

            //TODO Make Access token generation code common.
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Actort, "User"),
                new Claim("client_id", application.ClientId.ToString()),
                new Claim("session_id", refreshToken.SessionId.ToString())
            };
            if (organisationId.HasValue)
                claims.Add(new Claim("organisation_id", $"{organisationId}"));

            //If they are a merchant we add any roles they may have associated.
            string audience = "https://api.sobenz.com/consumer";
            if (scopes.Contains(Scopes.Merchant))
            {
                audience = "https://api.sobenz.com/merchant";
                var roles = (organisationId.HasValue && user.ContextualRoles.ContainsKey(organisationId.Value))
                    ? user.GlobalRoles.Union(user.ContextualRoles[organisationId.Value])
                    : user.GlobalRoles;
                foreach (var role in roles)
                    claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var accessToken = _tokenHandler.CreateEncodedJwt("sobenz.com", audience, new ClaimsIdentity(claims), DateTime.UtcNow.AddMinutes(-5), DateTime.Now.AddMinutes(5), DateTime.UtcNow, _signingCredentials);

            statusCode = HttpStatusCode.OK;
            var successResponse = new TokenResponseSuccess
            {
                AccessToken = accessToken,
                TokenType = TokenResponseType.AccessToken,
                ExpiresIn = (int)TimeSpan.FromMinutes(5).TotalSeconds,
                RefreshToken = refreshToken.Token
            };
            return Task.FromResult<ITokenResponse>(successResponse);
        }
    }
}
