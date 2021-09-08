using Microsoft.Azure.Cosmos;
using Microsoft.Azure.Cosmos.Linq;
using Sobenz.Authorization.Common.Interfaces;
using Sobenz.Authorization.Store.Cosmos.Models;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IdentityUser = Sobenz.Authorization.Common.Models.User;

namespace Sobenz.Authorization.Store.Cosmos
{
    internal sealed class CosmosUserStore : IUserStore
    {
        private readonly Container _userContainer;

        public CosmosUserStore(Container userContainer)
        {
            _userContainer = userContainer ?? throw new ArgumentNullException(nameof(userContainer));
        }

        public async Task<IdentityUser> GetUserAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var user = await _userContainer.ReadItemAsync<CosmosUserModel>(id.ToString(), new PartitionKey(id.ToString()), cancellationToken: cancellationToken);
            return CosmosUserModel.ToDomainModel(user);
        }

        public async Task<IdentityUser> GetUserByUsernameAsync(string username, CancellationToken cancellationToken = default)
        {
            var query = _userContainer.GetItemLinqQueryable<CosmosUserModel>();
            var iterator = query.Where(i => i.Username == username).ToFeedIterator();
            var user = (await iterator.ReadNextAsync(cancellationToken)).FirstOrDefault();
            return CosmosUserModel.ToDomainModel(user);
        }
    }
}
