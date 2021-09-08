using Microsoft.Azure.Cosmos;
using Microsoft.Azure.Cosmos.Linq;
using Sobenz.Authorization.Common.Interfaces;
using Sobenz.Authorization.Common.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Store.Cosmos
{
    internal sealed class CosmosApplicationStore : IApplicationStore
    {
        private readonly Container _applicationContainer;

        public CosmosApplicationStore(Container applicationContainer)
        {
            _applicationContainer = applicationContainer ?? throw new ArgumentNullException(nameof(applicationContainer));
        }

        public async Task<Application> GetAsync(Guid clientId, CancellationToken cancellationToken = default)
        {
            var application = await _applicationContainer.ReadItemAsync<Application>(clientId.ToString(), new PartitionKey(clientId.ToString()), cancellationToken: cancellationToken);
            return application;
        }

        public async Task<IEnumerable<Application>> List(CancellationToken cancellationToken = default)
        {
            var iterator = _applicationContainer.GetItemLinqQueryable<Application>().ToFeedIterator();
            return await iterator.ReadNextAsync(cancellationToken);
        }
    }
}
