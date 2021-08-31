using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sobenz.Authorization.Interfaces;
using Sobenz.Authorization.Models;
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TokenController : ControllerBase
    {
        private readonly IAuthorizationManager _authorizationManager;

        public TokenController(IAuthorizationManager authorizationManager)
        {
            _authorizationManager = authorizationManager ?? throw new ArgumentNullException(nameof(authorizationManager));
        }

        [HttpPost]
        [AllowAnonymous]
        [Consumes("application/json")]
        public Task<IActionResult> PostJson([FromBody] TokenRequest tokenRequest, CancellationToken cancellationToken = default)
        {
            return ProcessTokenRequestAsync(tokenRequest, cancellationToken);
        }

        [HttpPost]
        [AllowAnonymous]
        [Consumes("application/x-www-form-urlencoded")]
        public Task<IActionResult> PostTokenFormAsync([FromForm]TokenRequest tokenRequest, CancellationToken cancellationToken = default)
        {
            return ProcessTokenRequestAsync(tokenRequest, cancellationToken);
        }

        private async Task<IActionResult> ProcessTokenRequestAsync(TokenRequest tokenRequest, CancellationToken cancellationToken)
        {
            var getApplicationOperation = await _authorizationManager.AuthenticateApplicationAsync(tokenRequest.ClientId, tokenRequest.ClientSecret, tokenRequest.RedirectUri, tokenRequest.Scopes, cancellationToken);
            if(!getApplicationOperation.Success)
            {
                return StatusCode((int)getApplicationOperation.StatusCode, getApplicationOperation.TokenResponse);
            }
            var client = getApplicationOperation.Resource;

            AuthorizationOutcome outcome = null;

            switch (tokenRequest.GrantType)
            {
                case GrantType.AuthorizationCode:
                    outcome = await _authorizationManager.GenerateUserAccessTokenAsync(client, tokenRequest.Code, tokenRequest.CodeVerifier, tokenRequest.RedirectUri, tokenRequest.Scopes, tokenRequest.OrganisationId, cancellationToken);
                    break;
                case GrantType.ClientCredentials:
                    outcome = await _authorizationManager.GenerateApplicationAccessTokenAsync(client, tokenRequest.Scopes, tokenRequest.OrganisationId, cancellationToken);
                    break;
                case GrantType.Password:
                    outcome = await _authorizationManager.GenerateUserAccessTokenAsync(client, tokenRequest.Username, tokenRequest.Password, tokenRequest.Scopes, tokenRequest.OrganisationId, cancellationToken);
                    break;
                case GrantType.RefreshToken:
                    outcome = await _authorizationManager.RefreshAccessTokenAsync(client, tokenRequest.RefreshToken, tokenRequest.Scopes, tokenRequest.OrganisationId, cancellationToken);
                    break;
                default:
                    return BadRequest(new TokenResponseError { Error = TokenFailureError.InvalidGrant });
            }
            return StatusCode((int)outcome.StatusCode, outcome.TokenResponse);
        }
    }
}
