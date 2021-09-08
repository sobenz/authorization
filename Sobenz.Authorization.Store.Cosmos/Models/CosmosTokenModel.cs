using System;

namespace Sobenz.Authorization.Store.Cosmos.Models
{
    internal class CosmosTokenModel<TToken>
    {
        public string Id { get; set; }
        public string PartitionKey { get; set; }
        public string TokenType { get; set; }
        public TToken Token { get; set; }
        public int Ttl { get; set; }
    }
}
