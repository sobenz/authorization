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
        private readonly IApplicationService _applicationService;
        private readonly IAuthorizationManager _authorizationManager;

        public TokenController(IApplicationService applicationService, IAuthorizationManager authorizationManager)
        {
            _applicationService = applicationService ?? throw new ArgumentNullException(nameof(applicationService));
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
            //Check if we have a valid clientId at this point.
            if (!tokenRequest.ClientId.HasValue)
                return new BadRequestObjectResult(new TokenResponseError { Error = TokenFailureError.InvalidClient });

            //Ensure the client is validateed to the required level
            var client = await ValidateClient(tokenRequest.ClientId.Value, tokenRequest.ClientSecret, cancellationToken);
            if (client == null)
                return new UnauthorizedObjectResult(new TokenResponseError { Error = TokenFailureError.UnauthorizedClient });

            HttpStatusCode code;
            ITokenResponse response = null;

            switch (tokenRequest.GrantType)
            {
                case GrantType.AuthorizationCode:
                    response = await _authorizationManager.GenerateUserAccessTokenAsync(client, tokenRequest.Code, tokenRequest.CodeVerifier, tokenRequest.RedirectUri, tokenRequest.Scopes, tokenRequest.OrganisationId, out code, cancellationToken);
                    return StatusCode((int)code, response);
                case GrantType.ClientCredentials:
                    response = await _authorizationManager.GenerateApplicationAccessTokenAsync(client, tokenRequest.Scopes, tokenRequest.OrganisationId, out code, cancellationToken);
                    return StatusCode((int)code, response);
                case GrantType.Password:
                    response = await _authorizationManager.GenerateUserAccessTokenAsync(client, tokenRequest.Username, tokenRequest.Password, tokenRequest.Scopes, tokenRequest.OrganisationId, out code, cancellationToken);
                    return StatusCode((int)code, response);
                case GrantType.RefreshToken:
                    response = await _authorizationManager.RefreshAccessTokenAsync(client, tokenRequest.RefreshToken, tokenRequest.Scopes, tokenRequest.OrganisationId, out code, cancellationToken);
                    return StatusCode((int)code, response);
                default:
                    return BadRequest(new TokenResponseError { Error = TokenFailureError.InvalidGrant });
            }
        }

        private async Task<Application> ValidateClient(Guid clientId, string clientSecret, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(clientSecret))
                return await _applicationService.AuthenticateAsync(clientId, cancellationToken);
            else
                return await _applicationService.AuthenticateAsync(clientId, clientSecret, cancellationToken);
        }
    }
}
