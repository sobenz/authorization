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

        public AuthorizationManager()
        {
            //Should be an X509 Cert
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("Password12345678"));
            _signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
            _tokenHandler = new JwtSecurityTokenHandler();
        }

        public Task<ITokenResponse> GenerateApplicationAccessToken(Application application, IEnumerable<string> scopes, int? organisationId, out HttpStatusCode statusCode, CancellationToken cancellationToken)
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
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, application.ClientId.ToString())
            };
            if (organisationId.HasValue)
                claims.Add(new Claim("organisationId", $"{organisationId}"));

            var roles = (organisationId.HasValue && application.ContextualRoles.ContainsKey(organisationId.Value)) 
                ? application.GlobalRoles.Union(application.ContextualRoles[organisationId.Value])
                : application.GlobalRoles;
            foreach (var role in roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            var accessToken = _tokenHandler.CreateEncodedJwt("sobenz.com", "https://merchant.sobenz.com", new ClaimsIdentity(claims), DateTime.UtcNow.AddMinutes(-5), DateTime.Now.AddMinutes(5), DateTime.UtcNow, _signingCredentials);
            
            //TODO
            //5. Generate Refresh Token
            statusCode = HttpStatusCode.OK;
            var successResponse = new TokenResponseSuccess
            {
                AccessToken = accessToken,
                TokenType = TokenResponseType.AccessToken,
                ExpiresIn = (int)TimeSpan.FromMinutes(5).TotalSeconds,
                RefreshToken = "TODO"
            };
            return Task.FromResult<ITokenResponse>(successResponse);
        }
    }
}
