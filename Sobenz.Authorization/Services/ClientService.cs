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
        private readonly IClientSecretProvider _clientSecretProvider;
        private readonly IClientStore _clientStore;
        private readonly ITokenProvider _tokenProvider;
        private readonly ILogger _logger;

        public ClientService(IClientSecretProvider clientSecretProvider, IClientStore clientStore, ITokenProvider tokenProvider, ILogger<ClientService> logger)
        {
            _clientSecretProvider = clientSecretProvider ?? throw new ArgumentNullException(nameof(clientSecretProvider));
            _clientStore = clientStore ?? throw new ArgumentNullException(nameof(clientStore));
            _tokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<Tuple<Client,string>> CreateClientAsync(bool isConfidential, string name, IEnumerable<string> redirectUrls, IEnumerable<string> grantedScopes = null, IEnumerable<string> userAccessibleScopes = null, string logoUrl = null, IEnumerable<string> contacts = null, CancellationToken cancellationToken = default)
        {
            ValidateHasRedirectUrls(redirectUrls);
            ValidateScopes(grantedScopes, userAccessibleScopes);

            var client = new Client
            {
                Id = Guid.NewGuid(),
                IsConfidential = isConfidential,
                Name = name,
                RedirectionUrls = redirectUrls?.Select(s => new Uri(s)) ?? Enumerable.Empty<Uri>(),
                LogoUrl = logoUrl,
                Contacts = contacts ?? Enumerable.Empty<string>(),
                GrantedScopes = grantedScopes ?? Enumerable.Empty<string>(),
                UserAccessibleScopes = userAccessibleScopes ?? Enumerable.Empty<string>()            };

            //Create Default Secret if confidential client.
            string secret = null;
            if (isConfidential)
            {
                secret = _clientSecretProvider.Generate(out string secretHash);
                client.Secrets = new[]
                {
                    new ClientSecret { ActiveFrom = DateTime.UtcNow, ActiveTo = DateTime.UtcNow.AddDays(3650), Name = "Default", SecretHash = secretHash }
                };
            }
            client.RegistrationAccessToken = _tokenProvider.GenerateJwtAccessToken(client, null, Guid.NewGuid(), new[] { Scopes.ClientConfiguration });

            var created = await _clientStore.CreateClientAsync(client, cancellationToken);
            return Tuple.Create(created, secret);
        }

        public Task<Client> GetClientAsync(Guid clientId, CancellationToken cancellationToken)
        {
            return _clientStore.GetClientAsync(clientId, cancellationToken);
        }

        private void ValidateHasRedirectUrls(IEnumerable<string> redirectUrls)
        {
            //TODO Custom exception
            if ((redirectUrls == null) || !redirectUrls.Any())
            {
                throw new ArgumentException("No redirect urls provided.", nameof(redirectUrls));
            }
        }

        private void ValidateScopes(IEnumerable<string> grantedScopes, IEnumerable<string> userAccessibleScopes)
        {
            if ((grantedScopes != null) && grantedScopes.Any(gs => Scopes.ExplicitGrantScopes.Contains(gs)))
                throw new ArgumentException("Cannot grant explicity grant scopes to a client.");
            if ((userAccessibleScopes != null) && userAccessibleScopes.Any(uas => !Scopes.ExplicitGrantScopes.Contains(uas) || !Scopes.ImplicitGrantScopes.Contains(uas)))
                throw new ArgumentException("User accessible scopes must be in the scrictly defined list of scopes.");
        }
    }
}
