using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Sobenz.Authorization.Helpers;
using Sobenz.Authorization.Interfaces;
using Sobenz.Authorization.Models;
using System;
using System.ComponentModel.DataAnnotations;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class ClientsController : ControllerBase
    {
        private readonly IClientManager _clientManager;

        public ClientsController(IClientManager clientManager)
        {
            _clientManager = clientManager ?? throw new ArgumentNullException(nameof(clientManager));
        }

        [HttpPost]
        [Consumes("application/json")]
        [Authorize(SecurityHelper.PolicyNames.ClientRegistrationPolicy, AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<IActionResult> CreateClientAsync([FromBody][Required]ClientRegistrationRequest registrationRequest, CancellationToken cancellationToken = default)
        {
            var createdClient = await _clientManager.CreateClientAsync(
                isConfidential: (registrationRequest.ApplicationType == ApplicationType.Native),
                name: registrationRequest.ClientName,
                redirectUrls: registrationRequest.RedirectionUrls,
                logoUrl: registrationRequest.LogoUri,
                contacts: registrationRequest.Contacts,
                cancellationToken: cancellationToken);

            var resourceUri = new Uri($"{UriHelper.GetEncodedUrl(Request)}/{createdClient.Id}");

            return Created(resourceUri, createdClient);
        }

        [HttpGet]
        [Authorize(SecurityHelper.PolicyNames.ClientRegistrationPolicy, AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public Task<IActionResult> ListClientsAsync([FromQuery]string continuationToken = null, [FromQuery]int pageSize  = 20, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        [HttpGet]
        [Authorize(SecurityHelper.PolicyNames.ClientConfigurationPolicy, AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [Route("{clientId}")]
        public async Task<IActionResult> GetClientAsync(Guid clientId, CancellationToken cancellationToken = default)
        {
            var client = await _clientManager.GetClientAsync(clientId, cancellationToken);
            if (client == null)
                return NotFound();
            return Ok(client);
        }

        [HttpPut]
        [Consumes("application/json")]
        [Authorize(SecurityHelper.PolicyNames.ClientConfigurationPolicy, AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [Route("{clientId}")]
        public Task<IActionResult> UpdateClientDetailsAsync(Guid clientId, /*ClientDetails*/ CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        [HttpDelete]
        [Authorize(SecurityHelper.PolicyNames.ClientRegistrationPolicy, AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [Route("{clientId}")]
        public Task<IActionResult> DeleteClientAsync(Guid clientId, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        [HttpPost]
        [Consumes("application/json")]
        [Authorize(SecurityHelper.PolicyNames.ClientRegistrationPolicy, AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [Route("{clientId}/status")]
        public Task<IActionResult> SetClientStatusAsync(Guid clientId, /*Status*/ CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        [HttpPost]
        [Consumes("application/json")]
        [Authorize(SecurityHelper.PolicyNames.ClientRegistrationPolicy, AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [Route("{clientId}/scopes")]
        public Task<IActionResult> SetClientScopesAsync(Guid clientId, /*GrantedScopes,ConsumerScopes*/ CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        [HttpPost]
        [Consumes("application/json")]
        [Authorize(SecurityHelper.PolicyNames.ClientRegistrationPolicy, AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [Route("{clientId}/roles")]
        public Task<IActionResult> SetClientRolesAsync(Guid clientId, /*GlobalRoles,OrgRoles*/ CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        [HttpPost]
        [Consumes("application/json")]
        [Authorize(SecurityHelper.PolicyNames.ClientConfigurationPolicy, AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [Route("{clientId}/secrets")]
        public Task<IActionResult> CreateSecretAsync(Guid clientId, string secretName, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        [HttpDelete]
        [Consumes("application/json")]
        [Authorize(SecurityHelper.PolicyNames.ClientConfigurationPolicy, AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [Route("{clientId}/secrets")]
        public Task<IActionResult> SetClientStatusAsync(Guid clientId, string secretHash, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        [HttpPost]
        [Authorize(SecurityHelper.PolicyNames.ClientConfigurationPolicy, AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [Route("{clientId}/registration-token")]
        public Task<IActionResult> GenerateNewRegistrationAccessTokenAsync(Guid clientId, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
    }
}
