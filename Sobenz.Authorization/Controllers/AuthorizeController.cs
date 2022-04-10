using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Sobenz.Authorization.Common.Interfaces;
using Sobenz.Authorization.Common.Models;
using Sobenz.Authorization.Interfaces;
using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace Sobenz.Authorization.Controllers
{
    [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    [Route("authorize")]
    public class AuthorizeController : Controller
    {
        private readonly IClientStore _applicationService;
        private readonly IAuthorizationCodeService _authorizationCodeService;
        private readonly IAuthorizationManager _authorizationManager;
        private readonly IOptions<TokenOptions> _tokenOptions;

        public AuthorizeController(IClientStore applicationService, IAuthorizationManager authorizationManager, IAuthorizationCodeService authorizationCodeService, IOptions<TokenOptions> tokenOptions)
        {
            _applicationService = applicationService ?? throw new ArgumentNullException(nameof(applicationService));
            _authorizationCodeService = authorizationCodeService ?? throw new ArgumentNullException(nameof(authorizationCodeService));
            _authorizationManager = authorizationManager ?? throw new ArgumentNullException(nameof(authorizationManager));
            _tokenOptions = tokenOptions ?? throw new ArgumentNullException(nameof(tokenOptions));
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Index([FromQuery]AuthorizeRequest authorizeRequest, CancellationToken cancellationToken = default)
        {
            if (!ModelState.IsValid)
                return View("error"); //Missing required parameters
            var application = await _applicationService.GetClientAsync(authorizeRequest.ClientId.Value, cancellationToken);

            if (application == null)
                return View("error"); //Invalid client

            if (!application.IsConfidential && (string.IsNullOrEmpty(authorizeRequest.CodeChallenge) || !authorizeRequest.CodeChallengeMethod.HasValue))
                return View("error"); //Public client without PKCE Code challenge

            if (authorizeRequest.Scopes.Intersect(Scopes.ExplicitGrantScopes).Any(scope => !application.UserAccessibleScopes.Contains(scope)))
                return View("error"); //Application not allowed Scopes being requested.

            if (User.Identity.IsAuthenticated)
            {
                return View("grant", new GrantPermissionsViewModel { AuthorizationRequest = authorizeRequest, RequestingApplication = application });
            }
            else
                return View("login", authorizeRequest);
        }

        [HttpPost]
        [AllowAnonymous]
        public Task<IActionResult> Login([FromForm]AuthorizeOperation authorizationOperation, [FromQuery]AuthorizeRequest authorizeRequest, CancellationToken cancellationToken = default)
        {
            return authorizationOperation.Action switch
            {
                AuthorizeOperationType.Login => ProcessLoginAsync(authorizationOperation.Username, authorizationOperation.Password, authorizeRequest, cancellationToken),
                AuthorizeOperationType.Grant => ProcessGrantAsync(authorizeRequest, cancellationToken),
                _ => ProcessLogoutAsync(authorizeRequest),
            };
        }

        private async Task<IActionResult> ProcessGrantAsync(AuthorizeRequest authorizeRequest, CancellationToken cancellationToken)
        {
            if (!User.Identity.IsAuthenticated || !User.HasClaim(c => c.Type == ClaimTypes.Sid))
                return View("Error");

            if (!Guid.TryParse(User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Sid)?.Value, out Guid userId))
                return View("Error");

            var code = await _authorizationCodeService.CreateAuthorizationCodeAsync(authorizeRequest.ClientId.Value, userId, authorizeRequest.RedirectUri.ToString(), 
                authorizeRequest.Scopes, authorizeRequest.CodeChallenge, authorizeRequest.CodeChallengeMethod, authorizeRequest.Nonce, cancellationToken);

            var builder = new UriBuilder(authorizeRequest.RedirectUri);
            var query = HttpUtility.ParseQueryString(builder.Query);
            query["code"] = code;
            if (!string.IsNullOrEmpty(authorizeRequest.State))
                query["state"] = authorizeRequest.State;
            builder.Query = query.ToString();
            string url = builder.ToString();

            return Redirect(url);
        }

        private async Task<IActionResult> ProcessLoginAsync(string username, string password, AuthorizeRequest authorizeRequest, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                return View("login", authorizeRequest);

            var getUserOperation = await _authorizationManager.AuthenticateUserAsync(username, password, cancellationToken);

            if (!getUserOperation.Success)
            {
                ViewBag.Error = "Login Failed.";
                return View("login", authorizeRequest);
            }

            User user = getUserOperation.Resource;


            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Sid, user.Id.ToString()),
                new Claim(ClaimTypes.Name, username),
                new Claim(CustomClaims.FullName, $"{user.FirstName} {user.LastName}")
            };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties
            {
                AllowRefresh = true,
                ExpiresUtc = DateTime.Now.AddMinutes(10),
                IsPersistent = true,
                IssuedUtc = DateTime.UtcNow
            };

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);

            if (_tokenOptions.Value.BypassExplicitGrantScopes || !authorizeRequest.Scopes.Intersect(Scopes.ExplicitGrantScopes).Any())
            {
                var code = await _authorizationCodeService.CreateAuthorizationCodeAsync(authorizeRequest.ClientId.Value, user.Id, authorizeRequest.RedirectUri.ToString(),
                    authorizeRequest.Scopes, authorizeRequest.CodeChallenge, authorizeRequest.CodeChallengeMethod, authorizeRequest.Nonce, cancellationToken);

                var builder = new UriBuilder(authorizeRequest.RedirectUri);
                var query = HttpUtility.ParseQueryString(builder.Query);
                query["code"] = code;
                if (!string.IsNullOrEmpty(authorizeRequest.State))
                    query["state"] = authorizeRequest.State;
                builder.Query = query.ToString();
                string url = builder.ToString();

                return Redirect(url);
            }

            var app = await _applicationService.GetClientAsync(authorizeRequest.ClientId.Value, cancellationToken);
            var viewModel = new GrantPermissionsViewModel { RequestingApplication = app, AuthorizationRequest = authorizeRequest };
            return View("grant", viewModel);
        }

        private async Task<IActionResult> ProcessLogoutAsync(AuthorizeRequest authorizeRequest)
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return View("login", authorizeRequest);
        }
    }
}
