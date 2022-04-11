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

        public async Task<Client> CreateClientAsync(Client clientToCreate, CancellationToken cancellationToken = default)
        {
            ItemRequestOptions itemRequestOptions = new ItemRequestOptions { EnableContentResponseOnWrite = false };
            try
            {
                await _clientContainer.CreateItemAsync(ClientModel.FromDomainModel<CreateClientModel>(clientToCreate),
                    new PartitionKey(clientToCreate.Id.ToString()), itemRequestOptions, cancellationToken);
                return await GetClientAsync(clientToCreate.Id, cancellationToken);
            }
            catch(CosmosException ce) when (ce.StatusCode == HttpStatusCode.Conflict)
            {
                throw new ArgumentException("Client already exists.", nameof(clientToCreate), ce);
            }
        }

        public async Task<Client> GetClientAsync(Guid clientId, CancellationToken cancellationToken = default)
        {
            try
            {
                var clientModel = await _clientContainer.ReadItemAsync<ReadClientModel>(clientId.ToString(), new PartitionKey(clientId.ToString()), cancellationToken: cancellationToken);
                return ClientModel.ToDomainModel(clientModel);
            }
            catch (CosmosException ce) when (ce.StatusCode == HttpStatusCode.NotFound)
            {
                return null;
            }
        }

        public async Task<IEnumerable<Client>> ListClientsAsync(CancellationToken cancellationToken = default)
        {
            var iterator = _clientContainer.GetItemLinqQueryable<ReadClientModel>().ToFeedIterator();
            return (await iterator.ReadNextAsync(cancellationToken)).Select(m => ClientModel.ToDomainModel(m));
        }
    }
}
