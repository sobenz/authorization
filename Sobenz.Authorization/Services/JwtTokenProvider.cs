using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Sobenz.Authorization.Common.Models;
using Sobenz.Authorization.Helpers;
using Sobenz.Authorization.Interfaces;
using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace Sobenz.Authorization.Services
{
    public class JwtTokenProvider : ITokenProvider
    {
        private readonly ILogger _logger;
        private readonly SigningCredentials _signingCredentials;
        private readonly JwtSecurityTokenHandler _tokenHandler;
        private readonly IOptions<TokenOptions> _tokenOptions;

        public JwtTokenProvider(IOptions<TokenOptions> tokenOptions, ILogger<JwtTokenProvider> logger)
        {
            //TODO - Read from a cert provider.
            var certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine, OpenFlags.ReadOnly);
            var cert = certStore.Certificates.OfType<X509Certificate2>().First(c => c.FriendlyName == "SobenzCert");
            _signingCredentials = new X509SigningCredentials(cert, SecurityAlgorithms.RsaSha256);
            _tokenHandler = new JwtSecurityTokenHandler();

            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _tokenOptions = tokenOptions ?? throw new ArgumentNullException(nameof(tokenOptions));
        }

        public string GenerateJwtAccessToken(Subject subject, Client client, Guid sessionId, IEnumerable<string> scopes = null, IEnumerable<Claim> additionalClaims = null)
        {
            //Default Claims
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, subject.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Actort, subject.SubjectType.ToString()),
                new Claim(CustomClaims.SessionId, sessionId.ToString())
            };
            //Add the client Id claim if provided
            if (client != null)
                claims.Add(new Claim(CustomClaims.ClientId, client.Id.ToString()));

            //Get the organisation scope if there is one.
            Claim organisationClaim = additionalClaims?.FirstOrDefault(c => c.Type == CustomClaims.OrganisationId);
            int? organisationId = null;
            if (int.TryParse(organisationClaim?.Value, out int tmp))
                organisationId = tmp;
            else
                _logger.LogWarning($"Received '{nameof(CustomClaims.OrganisationId)} claim, however claim value could not be parsed.'");


            //If you are asking for the merchant scope, roles associated to the subjects current context are added as claims.
            string audience = _tokenOptions.Value.ConsumerAccessTokenAudience;
            if (scopes != null)
            {
                if (scopes.Contains(Scopes.ClientRegistration))
                {
                    audience = _tokenOptions.Value.MerchantAccessTokenAudience;
                    claims.Add(new Claim(CustomClaims.SecurityContext, SecurityHelper.SecurityContexts.ClientRegistration));
                }
                if (scopes.Contains(Scopes.ClientConfiguration))
                {
                    audience = _tokenOptions.Value.MerchantAccessTokenAudience;
                    claims.Add(new Claim(CustomClaims.SecurityContext, SecurityHelper.SecurityContexts.ClientConfiguration(subject.Id.ToString())));
                }
                if (scopes.Contains(Scopes.Merchant))
                {
                    audience = _tokenOptions.Value.MerchantAccessTokenAudience;
                    var roles = (organisationId.HasValue && subject.ContextualRoles.ContainsKey(organisationId.Value))
                        ? subject.GlobalRoles.Union(subject.ContextualRoles[organisationId.Value])
                        : subject.GlobalRoles;
                    foreach (var role in roles)
                        claims.Add(new Claim(ClaimTypes.Role, role));
                }
            }
            if (additionalClaims != null)
                claims.AddRange(additionalClaims);

            TimeSpan expiration = subject.SubjectType == SubjectType.Client ? _tokenOptions.Value.ApplicationAccessTokenLifetime : _tokenOptions.Value.UserAccessTokenLifetime;

            var accessToken = _tokenHandler.CreateEncodedJwt(_tokenOptions.Value.TokenIssuer, audience, new ClaimsIdentity(claims), DateTime.UtcNow, DateTime.UtcNow.Add(expiration), DateTime.UtcNow, _signingCredentials);
            return accessToken;
        }

        public string GenerateJwtIdentityToken(User subject, Client client, string nonce, IEnumerable<string> scopes = null)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, subject.Id.ToString())
            };
            if (scopes.Contains(Scopes.Profile))
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.GivenName, subject.FirstName));
                claims.Add(new Claim(JwtRegisteredClaimNames.FamilyName, subject.LastName));
                claims.Add(new Claim(JwtRegisteredClaimNames.Birthdate, subject.DateOfBirth.ToString(), ClaimValueTypes.Date));
            }
            if (scopes.Contains(Scopes.Email))
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Email, subject.EmailAddress));
                claims.Add(new Claim(CustomClaims.EmailVerified, subject.EmailVerified.ToString(), ClaimValueTypes.Boolean));
            }
            if (!string.IsNullOrEmpty(nonce))
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));
            }

            TimeSpan expiration = _tokenOptions.Value.IdentityTokenLifetime;
            string token = _tokenHandler.CreateEncodedJwt(_tokenOptions.Value.TokenIssuer, client.Id.ToString(), new ClaimsIdentity(claims), DateTime.UtcNow, DateTime.Now.Add(expiration), DateTime.UtcNow, _signingCredentials);

            return token;
        }
    }
}
