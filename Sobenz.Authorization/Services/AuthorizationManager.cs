using Sobenz.Authorization.Abstractions.Models;
using Sobenz.Authorization.Common.Interfaces;
using Sobenz.Authorization.Common.Models;
using Sobenz.Authorization.Interfaces;
using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Services
{
    internal class AuthorizationManager : IAuthorizationManager
    {
        private readonly ITokenProvider _tokenProvider;
        private readonly IPasswordHasher _passwordHasher;
        private readonly IClientStore _applicationService;
        private readonly IAuthorizationCodeService _authorizationCodeService;
        private readonly IRefreshTokenService _refreshTokenService;
        private readonly IUserStore _userService;

        public AuthorizationManager(ITokenProvider tokenProvider, IPasswordHasher passwordHasher, IClientStore applicationService, IAuthorizationCodeService authorizationCodeService, IRefreshTokenService refreshTokenService, IUserStore userService)
        {
            _tokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
            _passwordHasher = passwordHasher ?? throw new ArgumentNullException(nameof(passwordHasher));
            _applicationService = applicationService ?? throw new ArgumentNullException(nameof(applicationService));
            _authorizationCodeService = authorizationCodeService ?? throw new ArgumentNullException(nameof(authorizationCodeService));
            _refreshTokenService = refreshTokenService ?? throw new ArgumentNullException(nameof(refreshTokenService));
            _userService = userService ?? throw new ArgumentNullException(nameof(userService));
        }

        public async Task<AuthorizationOutcome<Client>> AuthenticateApplicationAsync(Guid? clientId, string clientSecret, Uri redirectionUrl, IEnumerable<string> scopes, CancellationToken cancellationToken = default)
        {
            //Ensure that the Client Identifier is a valid Guid
            if (!clientId.HasValue)
            {
                return AuthorizationOutcome<Client>.Fail(new TokenResponseError(TokenFailureError.InvalidRequest, "Missing or malformed client id."), HttpStatusCode.BadRequest);
            }

            //Check that the application exists and is active.
            var application = await _applicationService.GetClientAsync(clientId.Value, cancellationToken);
            if ((application == null) || (application.State != ClientState.Active))
            {
                return AuthorizationOutcome<Client>.Fail(new TokenResponseError(TokenFailureError.InvalidClient), HttpStatusCode.Unauthorized);
            }

            //If we are dealing with a Confidential Client then ensure the Secret Matches
            if (application.IsConfidential)
            {
                var challenge = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(clientSecret ?? string.Empty)));
                if (!application.Secrets.Any(s => s.SecretHash == challenge && DateTime.UtcNow > s.ActiveFrom && DateTime.UtcNow < s.ActiveTo))
                {
                    return AuthorizationOutcome<Client>.Fail(new TokenResponseError(TokenFailureError.InvalidClient), HttpStatusCode.Unauthorized);
                }
            }

            //If provided, check that the redirection url matches what we have registered against the application.
            if ((redirectionUrl != null) && !application.RedirectionUrls.Contains(redirectionUrl))
            {
                return AuthorizationOutcome<Client>.Fail(new TokenResponseError(TokenFailureError.AccessDenied, "Invalid redirection url."), HttpStatusCode.Unauthorized);
            }

            //Check that any scopes associated with this request have been granted to the application.
            if ((scopes != null) && !scopes.All(s => application.GrantedScopes.Contains(s, StringComparer.Ordinal)))
            {
                return AuthorizationOutcome<Client>.Fail(new TokenResponseError(TokenFailureError.InvalidScope, "One or more scopes not allowed."), HttpStatusCode.Unauthorized);
            }

            //Now we are good to return as a successful authentication of the client.
            return AuthorizationOutcome<Client>.Succeed(application);
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

        public async Task<AuthorizationOutcome> GenerateApplicationAccessTokenAsync(Client client, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken)
        {
            if (!client.IsConfidential)
                return AuthorizationOutcome.Fail(new TokenResponseError(TokenFailureError.InvalidClient, "Public clients not allowed."), HttpStatusCode.BadRequest);

            if (!client.GrantedScopes.Contains(Scopes.Merchant))
                return AuthorizationOutcome.Fail(new TokenResponseError(TokenFailureError.InvalidClient, "Client has not been granted correct scopes"), HttpStatusCode.Forbidden);
            
            var refreshToken = await _refreshTokenService.CreateTokenAsync(SubjectType.Client, client.Id, client.Id, scopes, organisationId, cancellationToken);
            var accessToken = GenerateSubjectAccessToken(client, null, organisationId, refreshToken.SessionId, scopes);

            int expirationSeconds = (int)TimeSpan.FromMinutes(5).TotalSeconds;
            return AuthorizationOutcome.Succeed(new TokenResponseSuccess(TokenResponseType.AccessToken, accessToken, refreshToken.Token, expirationSeconds, scopes));
        }

        public async Task<AuthorizationOutcome> GenerateUserAccessTokenAsync(Client client, string authorizationCode, string codeVerifier, Uri redirectUri, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken)
        {
            //TODO Check Failure Scenarios HTTP Status Codes
            if (!client.IsConfidential && string.IsNullOrEmpty(codeVerifier))
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
            var refreshToken = await _refreshTokenService.CreateTokenAsync(SubjectType.User, user.Id, client.Id, activeScopes, organisationId, cancellationToken);
            var accessToken = GenerateSubjectAccessToken(user, client, organisationId, refreshToken.SessionId, activeScopes);

            string idToken = null;
            if (activeScopes.Contains(Scopes.OpenId))
                idToken = _tokenProvider.GenerateJwtIdentityToken(user, client, code.Nonce, activeScopes);

            int expirationSeconds = (int)TimeSpan.FromMinutes(5).TotalSeconds;
            return AuthorizationOutcome.Succeed(new TokenResponseSuccess(TokenResponseType.AccessToken, accessToken, refreshToken.Token, expirationSeconds, scopes, idToken));
        }

        public async Task<AuthorizationOutcome> GenerateUserAccessTokenAsync(Client client, string username, string password, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken)
        {
            if (!client.IsConfidential)
                return AuthorizationOutcome.Fail(new TokenResponseError(TokenFailureError.InvalidClient, "Public clients not allowed with the Password grant."), HttpStatusCode.BadRequest);

            var getUserOpperation = await AuthenticateUserAsync(username, password, cancellationToken);
            if (!getUserOpperation.Success)
                return AuthorizationOutcome.Fail(getUserOpperation.TokenResponse, getUserOpperation.StatusCode);

            User user = getUserOpperation.Resource;

            var refreshToken = _refreshTokenService.CreateTokenAsync(SubjectType.User, user.Id, client.Id, scopes, organisationId, cancellationToken).Result;
            var accessToken = GenerateSubjectAccessToken(user, client, organisationId, refreshToken.SessionId, scopes);

            int expirationSeconds = (int)TimeSpan.FromMinutes(5).TotalSeconds;
            return AuthorizationOutcome.Succeed(new TokenResponseSuccess(TokenResponseType.AccessToken, accessToken, refreshToken.Token, expirationSeconds, scopes));
        }

        public async Task<AuthorizationOutcome> RefreshAccessTokenAsync(Client client, string token, IEnumerable<string> scopes, int? organisationId, CancellationToken cancellationToken)
        {
            var refreshToken = await _refreshTokenService.RefreshTokenAsync(token, client.Id, scopes, organisationId, cancellationToken);
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
                accessToken = GenerateSubjectAccessToken(user, client, organisationId, refreshToken.SessionId, activeScopes);

                if (activeScopes.Contains(Scopes.OpenId))
                    idToken = _tokenProvider.GenerateJwtIdentityToken(user, client, string.Empty, activeScopes);
            }
            else
                accessToken = GenerateSubjectAccessToken(client, null, organisationId, refreshToken.SessionId, activeScopes);

            int expirationSeconds = (int)TimeSpan.FromMinutes(5).TotalSeconds;
            return AuthorizationOutcome.Succeed(new TokenResponseSuccess(TokenResponseType.AccessToken, accessToken, refreshToken.Token, expirationSeconds, activeScopes, idToken));
        }

        private string GenerateSubjectAccessToken(Subject subject, Client client, int? organisationId, Guid sessionId, IEnumerable<string> scopes)
        {
            var customClaims = organisationId.HasValue ?
                new Claim[] { new Claim(CustomClaims.OrganisationId, organisationId.Value.ToString()) } : null;

            return _tokenProvider.GenerateJwtAccessToken(subject, client, sessionId, scopes, customClaims);
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
