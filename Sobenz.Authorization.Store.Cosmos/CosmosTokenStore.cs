using Microsoft.Azure.Cosmos;
using Sobenz.Authorization.Common.Interfaces;
using Sobenz.Authorization.Store.Cosmos.Models;
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Store.Cosmos
{
    internal sealed class CosmosTokenStore : ITokenStore
    {
        private readonly Container _tokenContainer;

        public CosmosTokenStore(Container tokenContainer)
        {
            _tokenContainer = tokenContainer ?? throw new ArgumentNullException(nameof(tokenContainer));
        }

        public async Task DeleteTokenAsync<TToken>(string tokenKey, CancellationToken cancellationToken = default)
        {
            if ((tokenKey == null) || (tokenKey.Length < 4))
                return;
            await _tokenContainer.DeleteItemAsync<CosmosTokenModel<TToken>>(tokenKey, new PartitionKey(GenerateTokenPartitionKey(tokenKey)), cancellationToken: cancellationToken);
        }

        public async Task<TToken> GetTokenAsync<TToken>(string tokenKey, CancellationToken cancellationToken = default)
        {
            try
            {
                if ((tokenKey == null) || (tokenKey.Length < 4))
                    return default(TToken);
                var response = await _tokenContainer.ReadItemAsync<CosmosTokenModel<TToken>>(tokenKey, new PartitionKey(GenerateTokenPartitionKey(tokenKey)), cancellationToken: cancellationToken);
                return response.Resource.Token;
            }
            catch(CosmosException ce) when (ce.StatusCode == HttpStatusCode.NotFound)
            {
                return default;
            }
        }

        public async Task UpsertTokenAsync<TToken>(string tokenKey, TToken token, TimeSpan ttl, CancellationToken cancellationToken = default)
        {
            string partitionKey = GenerateTokenPartitionKey(tokenKey);
            var entity = new CosmosTokenModel<TToken>
            {
                Id = tokenKey,
                PartitionKey = partitionKey,
                TokenType = typeof(TToken).Name,
                Token = token,
                Ttl = (int)ttl.TotalSeconds
            };

            await _tokenContainer.UpsertItemAsync(entity, new PartitionKey(partitionKey), cancellationToken: cancellationToken);
        }

        private static string GenerateTokenPartitionKey(string tokenKey)
        {
            return tokenKey.ToUpper().Substring(0, 4);
        }
    }
}
