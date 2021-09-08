using System;

namespace Sobenz.Authorization.Store.Cosmos
{
    public class CosmosStoreOptions
    {
        public string ConnectionString { get; set; }
        public string DatabaseName { get; set; }
    }
}
