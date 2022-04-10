using Microsoft.Azure.Cosmos;
using Microsoft.Azure.Cosmos.Linq;
using Sobenz.Authorization.Common.Interfaces;
using Sobenz.Authorization.Common.Models;
using Sobenz.Authorization.Store.Cosmos.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Store.Cosmos
{
    internal sealed class CosmosClientStore : IClientStore
    {
        private readonly Container _clientContainer;

        public CosmosClientStore(Container clientContainer)
        {
            _clientContainer = clientContainer ?? throw new ArgumentNullException(nameof(clientContainer));
        }

        public async Task<Client> GetClientAsync(Guid clientId, CancellationToken cancellationToken = default)
        {
            try
            {
                var clientModel = await _clientContainer.ReadItemAsync<CosmosClientModel>(clientId.ToString(), new PartitionKey(clientId.ToString()), cancellationToken: cancellationToken);
                return CosmosClientModel.ToDomainModel(clientModel);
            }
            catch (CosmosException ce) when (ce.StatusCode == HttpStatusCode.NotFound)
            {
                return null;
            }
        }

        public async Task<IEnumerable<Client>> ListClientsAsync(CancellationToken cancellationToken = default)
        {
            var iterator = _clientContainer.GetItemLinqQueryable<CosmosClientModel>().ToFeedIterator();
            return (await iterator.ReadNextAsync(cancellationToken)).Select(m => CosmosClientModel.ToDomainModel(m));
        }
    }
}
