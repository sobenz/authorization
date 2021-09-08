using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Sobenz.Authorization.Abstractions.Models;
using Sobenz.Authorization.Common.Interfaces;
using Sobenz.Authorization.Common.Models;
using Sobenz.Authorization.Interfaces;
using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Services
{
    internal class AuthorizationManager : IAuthorizationManager
    {
        private readonly JwtSecurityTokenHandler _tokenHandler;
        private readonly SigningCredentials _signingCredentials;

        private readonly IOptions<TokenOptions> _tokenOptions;
        private readonly IPasswordHasher _passwordHasher;
        private readonly IApplicationStore _applicationService;
        private readonly IAuthorizationCodeService _authorizationCodeService;
        private readonly IRefreshTokenService _refreshTokenService;
        private readonly IUserStore _userService;

        public AuthorizationManager(IOptions<TokenOptions> tokenOptions, IPasswordHasher passwordHasher, IApplicationStore applicationService, IAuthorizationCodeService authorizationCodeService, IRefreshTokenService refreshTokenService, IUserStore userService)
        {
            //TODO - Read from a cert provider.
            var certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine, OpenFlags.ReadOnly);
            var cert = certStore.Certificates.OfType<X509Certificate2>().First(c => c.FriendlyName == "SobenzCert");
            _signingCredentials = new X509SigningCredentials(cert, SecurityAlgorithms.RsaSha256);
            _tokenHandler = new JwtSecurityTokenHandler();

            _tokenOptions = tokenOptions ?? throw new ArgumentNullException(nameof(tokenOptions));
            _passwordHasher = passwordHasher ?? throw new ArgumentNullException(nameof(passwordHasher));
            _applicationService = applicationService ?? throw new ArgumentNullException(nameof(applicationService));
            _authorizationCodeService = authorizationCodeService ?? throw new ArgumentNullException(nameof(authorizationCodeService));
            _refreshTokenService = refreshTokenService ?? throw new ArgumentNullException(nameof(refreshTokenService));
            _userService = userService ?? throw new ArgumentNullException(nameof(userService));
        }

        public async Task<AuthorizationOutcome<Application>> AuthenticateApplicationAsync(Guid? clientId, string clientSecret, Uri redirectionUrl, IEnumerable<string> scopes, CancellationToken cancellationToken = default)
        {
            //Ensure that the Client Identifier is a valid Guid
            if (!clientId.HasValue)
            {
                return AuthorizationOutcome<Application>.Fail(new TokenResponseError(TokenFailureError.InvalidRequest, "Missing or malformed client id."), HttpStatusCode.BadRequest);
            }

            //Check that the application exists and is active.
            var application = await _applicationService.GetAsync(clientId.Value, cancellationToken);
            if ((application == null) || (application.State != ApplicationState.Active))
            {
                return AuthorizationOutcome<Application>.Fail(new TokenResponseError(TokenFailureError.InvalidClient), HttpStatusCode.Unauthorized);
            }

            //If we are dealing with a Confidential Client then ensure the Secret Matches
            if (application.IsConfidential)
            {
                var challenge = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(clientSecret ?? string.Empty)));
                if (!application.Secrets.Any(s => s.SecretHash == challenge && DateTime.UtcNow > s.ActiveFrom && DateTime.UtcNow < s.ActiveTo))
                {
                    return AuthorizationOutcome<Application>.Fail(new TokenResponseError(TokenFailureError.InvalidClient), HttpStatusCode.Unauthorized);
                }
            }

            //If provided, check that the redirection url matches what we have registered against the application.
            if ((redirectionUrl != null) && !application.RedirectionUrls.Contains(redirectionUrl))
            {
                return AuthorizationOutcome<Application>.Fail(new TokenResponseError(TokenFailureError.AccessDenied, "Invalid redirection url."), HttpStatusCode.Unauthorized);
            }

            //Check that any scopes associated with this request have been granted to the application.
            if ((scopes != null) && !scopes.All(s => application.AllowedScopes.Contains(s, StringComparer.Ordinal)))
            {
                return AuthorizationOutcome<Application>.Fail(new TokenResponseError(TokenFailureError.InvalidScope, "One or more scopes not allowed."), HttpStatusCode.Unauthorized);
            }

            //Now we are good to return as a successful authentication of the client.
            return AuthorizationOutcome<Application>.Succeed(application);
        }

        public async Task<AuthorizationOutcome<User>> AuthenticateUserAsync(string username, string password, CancellationToken cancellationToken = default)
        {
            //Attempt to retrieve the user by user name first.
            var user = await _userService.GetUserByUsernameAsync(username, cancellationToken);

            //If the user exists and is active now verify their password.
            if (user != null && (user.State != UserState.Deactivated))
            {
                var identity = user.Identities.OfType<UserPasswordIdentity>().FirstOrDefault();
                if (identity != null)
                {
                    var pwdHash = await _passwordHasher.HashPasswordAsync(password, identity.Salt);
                    if (pwdHash == identity.Password)
                        return AuthorizationOutcome<User>.Succeed(user);
                }
            }
            return AuthorizationOutcome<User>.Fail(new TokenResponseError(TokenFailureError.AccessDenied), HttpStatusCode.Unauthorized);
        }

        public async Task<AuthorizationOutcome> GenerateApplicationAccessTokenAsync(Application application, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken)
        {
            if (!application.IsConfidential)
                return AuthorizationOutcome.Fail(new TokenResponseError(TokenFailureError.InvalidClient, "Public clients not allowed."), HttpStatusCode.BadRequest);

            if (!application.AllowedScopes.Contains(Scopes.Merchant))
                return AuthorizationOutcome.Fail(new TokenResponseError(TokenFailureError.InvalidClient, "Client has not been granted correct scopes"), HttpStatusCode.Forbidden);
            
            var refreshToken = await _refreshTokenService.CreateTokenAsync(SubjectType.Application, application.Id, null, scopes, organisationId, cancellationToken);
            var accessToken = GenerateSubjectAccessToken(application, null, organisationId, refreshToken.SessionId, scopes);

            int expirationSeconds = (int)TimeSpan.FromMinutes(5).TotalSeconds;
            return AuthorizationOutcome.Succeed(new TokenResponseSuccess(TokenResponseType.AccessToken, accessToken, refreshToken.Token, expirationSeconds, scopes));
        }

        public async Task<AuthorizationOutcome> GenerateUserAccessTokenAsync(Application application, string authorizationCode, string codeVerifier, Uri redirectUri, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken)
        {
            //TODO Check Failure Scenarios HTTP Status Codes
            if (!application.IsConfidential && string.IsNullOrEmpty(codeVerifier))
                return AuthorizationOutcome.Fail(new TokenResponseError(TokenFailureError.InvalidClient, "Public clients must provide PKCE verifier."), HttpStatusCode.BadRequest);

            var code = await _authorizationCodeService.ValidateCodeAsync(authorizationCode, cancellationToken);
            if (code == null)
                return AuthorizationOutcome.Fail(new TokenResponseError(TokenFailureError.UnauthorizedClient, "Invalid or expired Authorization Code"), HttpStatusCode.Unauthorized);

            if (redirectUri.ToString() != code.RedirectionUri)
                return AuthorizationOutcome.Fail(new TokenResponseError(TokenFailureError.InvalidClient, "Redirect Uri mismatch."), HttpStatusCode.BadRequest);

            if ((scopes != null) && scopes.Any(s => !code.GrantedScopes.Contains(s)))
                return AuthorizationOutcome.Fail(new TokenResponseError(TokenFailureError.InvalidScope, "Scopes are not subset of orginal grant."), HttpStatusCode.BadRequest);

            if (!VerifyPKCE(codeVerifier, code.CodeChallenge, code.CodeChallengeMethod))
                return AuthorizationOutcome.Fail(new TokenResponseError(TokenFailureError.AccessDenied, "Code Verification Failed."), HttpStatusCode.Unauthorized);

            var user = await _userService.GetUserAsync(code.GrantingUserId, cancellationToken);
            if ((user == null) || (user.State != UserState.Active))
                return AuthorizationOutcome.Fail(new TokenResponseError(TokenFailureError.AccessDenied, "Authentication Failed."), HttpStatusCode.Unauthorized);

            var activeScopes = scopes ?? code.GrantedScopes;
            var refreshToken = await _refreshTokenService.CreateTokenAsync(SubjectType.User, user.Id, application.Id, activeScopes, organisationId, cancellationToken);
            var accessToken = GenerateSubjectAccessToken(user, application, organisationId, refreshToken.SessionId, activeScopes);

            string idToken = null;
            if (activeScopes.Contains(Scopes.Identity) || activeScopes.Contains(Scopes.OpenId))
                idToken = GenerateUserIdentityToken(user, application, code.Nonce, activeScopes);

            int expirationSeconds = (int)TimeSpan.FromMinutes(5).TotalSeconds;
            return AuthorizationOutcome.Succeed(new TokenResponseSuccess(TokenResponseType.AccessToken, accessToken, refreshToken.Token, expirationSeconds, scopes, idToken));
        }

        public async Task<AuthorizationOutcome> GenerateUserAccessTokenAsync(Application application, string username, string password, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken)
        {
            if (!application.IsConfidential)
                return AuthorizationOutcome.Fail(new TokenResponseError(TokenFailureError.InvalidClient, "Public clients not allowed with the Password grant."), HttpStatusCode.BadRequest);

            var getUserOpperation = await AuthenticateUserAsync(username, password, cancellationToken);
            if (!getUserOpperation.Success)
                return AuthorizationOutcome.Fail(getUserOpperation.TokenResponse, getUserOpperation.StatusCode);

            User user = getUserOpperation.Resource;

            var refreshToken = _refreshTokenService.CreateTokenAsync(SubjectType.User, user.Id, application.Id, scopes, organisationId, cancellationToken).Result;
            var accessToken = GenerateSubjectAccessToken(user, application, organisationId, refreshToken.SessionId, scopes);

            int expirationSeconds = (int)TimeSpan.FromMinutes(5).TotalSeconds;
            return AuthorizationOutcome.Succeed(new TokenResponseSuccess(TokenResponseType.AccessToken, accessToken, refreshToken.Token, expirationSeconds, scopes));
        }

        public async Task<AuthorizationOutcome> RefreshAccessTokenAsync(Application application, string token, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken)
        {
            var refreshToken = await _refreshTokenService.RefreshTokenAsync(token, application.Id, scopes, organisationId, cancellationToken);
            if (refreshToken == null)
                return AuthorizationOutcome.Fail(new TokenResponseError(TokenFailureError.AccessDenied, "Authentication Failed."), HttpStatusCode.Unauthorized);

            //If no scopes are defined fall back to default scopes orginally associated with authorization.
            var activeScopes = scopes ?? refreshToken.Scopes;

            string accessToken;
            string idToken = null;
            if (refreshToken.SubjectType == SubjectType.User)
            {
                var user = await _userService.GetUserAsync(refreshToken.Subject, cancellationToken);

                if ((user == null) || (user.State != UserState.Active))
                    return AuthorizationOutcome.Fail(new TokenResponseError(TokenFailureError.AccessDenied, "User is not active."), HttpStatusCode.Unauthorized);
                accessToken = GenerateSubjectAccessToken(user, application, organisationId, refreshToken.SessionId, activeScopes);

                if (activeScopes.Contains(Scopes.Identity) || activeScopes.Contains(Scopes.OpenId))
                    idToken = GenerateUserIdentityToken(user, application, string.Empty, activeScopes);
            }
            else
                accessToken = GenerateSubjectAccessToken(application, null, organisationId, refreshToken.SessionId, activeScopes);

            int expirationSeconds = (int)TimeSpan.FromMinutes(5).TotalSeconds;
            return AuthorizationOutcome.Succeed(new TokenResponseSuccess(TokenResponseType.AccessToken, accessToken, refreshToken.Token, expirationSeconds, activeScopes, idToken));
        }

        private string GenerateSubjectAccessToken(Subject subject, Application clientApplication, int? organisationId, Guid sessionId, IEnumerable<string> scopes)
        {
            //Default Claims
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, subject.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Actort, subject.SubjectType.ToString()),
                new Claim(CustomClaims.SessionId, sessionId.ToString())
            };
            //Add the client Id claim if provided
            if (clientApplication != null)
                claims.Add(new Claim(CustomClaims.ClientId, clientApplication.Id.ToString()));

            //Contextual scope if there is one.
            if (organisationId.HasValue)
                claims.Add(new Claim(CustomClaims.OrganisationId, $"{organisationId}"));

            //If you are asking for the merchant scope, roles associated to the subjects current context are added as claims.
            string audience = _tokenOptions.Value.ConsumerAccessTokenAudience.ToString();
            if ((scopes != null) && scopes.Contains(Scopes.Merchant))
            {
                audience = _tokenOptions.Value.MerchantAccessTokenAudience.ToString();
                var roles = (organisationId.HasValue && subject.ContextualRoles.ContainsKey(organisationId.Value))
                    ? subject.GlobalRoles.Union(subject.ContextualRoles[organisationId.Value])
                    : subject.GlobalRoles;
                foreach (var role in roles)
                    claims.Add(new Claim(ClaimTypes.Role, role));
            }

            TimeSpan expiration = subject.SubjectType == SubjectType.Application ? _tokenOptions.Value.ApplicationAccessTokenLifetime : _tokenOptions.Value.UserAccessTokenLifetime;

            var accessToken = _tokenHandler.CreateEncodedJwt(_tokenOptions.Value.TokenIssuer, audience, new ClaimsIdentity(claims), DateTime.UtcNow, DateTime.UtcNow.Add(expiration), DateTime.UtcNow, _signingCredentials);
            return accessToken;
        }

        private string GenerateUserIdentityToken(User user, Application app, string nonce, IEnumerable<string> scopes)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString())
            };
            if (scopes.Contains(Scopes.Profile))
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.GivenName, user.FirstName));
                claims.Add(new Claim(JwtRegisteredClaimNames.FamilyName, user.LastName));
                claims.Add(new Claim(JwtRegisteredClaimNames.Birthdate, user.DateOfBirth.ToString(), ClaimValueTypes.Date));
            }
            if (scopes.Contains(Scopes.Email))
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.EmailAddress));
                claims.Add(new Claim(CustomClaims.EmailVerified, user.EmailVerified.ToString(), ClaimValueTypes.Boolean));
            }
            if (!string.IsNullOrEmpty(nonce))
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));
            }

            TimeSpan expiration = _tokenOptions.Value.IdentityTokenLifetime;
            string token = _tokenHandler.CreateEncodedJwt(_tokenOptions.Value.TokenIssuer, app.Id.ToString(), new ClaimsIdentity(claims), DateTime.UtcNow, DateTime.Now.Add(expiration), DateTime.UtcNow, _signingCredentials);

            return token;
        }

        private static bool VerifyPKCE(string verifier, string challenge, CodeChallengeMethod? method)
        {
            //If there was no challenge then there is nothing to verify.
            if (!method.HasValue)
                return true;

            bool codeVerified = false;
            switch (method)
            {
                case CodeChallengeMethod.Plain:
                    //Simple Match
                    codeVerified = verifier == challenge;
                    break;
                case CodeChallengeMethod.SHA256:
                    //Hash the compare as defined in RFC7632 
                    var test = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier ?? string.Empty)), Base64FormattingOptions.None);
                    test = test.Split('=')[0]; // Remove any trailing '='s
                    test = test.Replace('+', '-'); // 62nd char of encoding
                    test = test.Replace('/', '_'); // 63rd char of encoding
                    codeVerified = test == challenge;
                    break;
            }
            return codeVerified;
        }
    }
}
