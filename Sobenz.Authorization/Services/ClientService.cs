using Microsoft.Extensions.Logging;
using Sobenz.Authorization.Common.Interfaces;
using Sobenz.Authorization.Common.Models;
using Sobenz.Authorization.Interfaces;
using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Services
{
    internal class ClientService : IClientManager
    {
        private readonly IClientStore _clientStore;
        private readonly ITokenProvider _tokenProvider;
        private readonly ILogger _logger;

        public ClientService(IClientStore clientStore, ITokenProvider tokenProvider, ILogger<ClientService> logger)
        {
            //TODO Extract Token Creation into a seperate class.
            _clientStore = clientStore ?? throw new ArgumentNullException(nameof(clientStore));
            _tokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public Task<Client> CreateClientAsync(bool isConfidential, string name, IEnumerable<string> redirectUrls, string logoUrl = null, IEnumerable<string> contacts = null, CancellationToken cancellationToken = default)
        {
            ValidateHasRedirectUrls(redirectUrls);

            var client = new Client
            {
                Id = Guid.NewGuid(),
                IsConfidential = isConfidential,
                Name = name,
                RedirectionUrls = redirectUrls?.Select(s => new Uri(s)) ?? Enumerable.Empty<Uri>(),
                LogoUrl = logoUrl,
                Contacts = contacts ?? Enumerable.Empty<string>()
            };
            client.RegistrationAccessToken = _tokenProvider.GenerateJwtAccessToken(client, null, Guid.NewGuid(), new[] { Scopes.ClientConfiguration });
            //TODO Create Client in Store
            return null;
        }

        private string BuildRegistrationToken(Guid clientId)
        {
            return string.Empty;
        }

        private void ValidateHasRedirectUrls(IEnumerable<string> redirectUrls)
        {
            //TODO Custom exception
            if ((redirectUrls == null) || !redirectUrls.Any())
            {
                throw new ArgumentException("No redirect urls provided.", nameof(redirectUrls));
            }
        }
    }
}
