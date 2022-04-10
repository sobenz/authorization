using Microsoft.Azure.Cosmos;
using Microsoft.Azure.Cosmos.Fluent;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Sobenz.Authorization.Common.Interfaces;
using Sobenz.Authorization.Store.Cosmos;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class ServiceCollectionExtensions
    {
        private const string ApplicationContainerName = "application";
        private const string TokenContainerName = "token";
        private const string UserContainerName = "user";

        public static IServiceCollection AddCosmosIdentityStore(this IServiceCollection services, IConfiguration configuration)
        { 
            services.Configure<CosmosStoreOptions>(configuration.GetSection("CosmosDbSettings"));
            services.AddSingleton(sp =>
            {
                var config = sp.GetRequiredService<IOptions<CosmosStoreOptions>>();
                var client = new CosmosClientBuilder(config.Value.ConnectionString)
                    .WithSerializerOptions(new CosmosSerializationOptions { PropertyNamingPolicy = CosmosPropertyNamingPolicy.CamelCase })
                    .Build();
                return client;
            });
            services.AddSingleton<IClientStore>(sp =>
            {
                var config = sp.GetRequiredService<IOptions<CosmosStoreOptions>>();
                var client = sp.GetRequiredService<CosmosClient>();
                var container = client.GetContainer(config.Value.DatabaseName, ApplicationContainerName);
                var appStore = new CosmosClientStore(container);
                return appStore;
            });
            services.AddSingleton<ITokenStore>(sp =>
            {
                var config = sp.GetRequiredService<IOptions<CosmosStoreOptions>>();
                var client = sp.GetRequiredService<CosmosClient>();
                var container = client.GetContainer(config.Value.DatabaseName, TokenContainerName);
                var tokenStore = new CosmosTokenStore(container);
                return tokenStore;
            });

            services.AddSingleton<IUserStore>(sp =>
            {
                var config = sp.GetRequiredService<IOptions<CosmosStoreOptions>>();
                var client = sp.GetRequiredService<CosmosClient>();
                var container = client.GetContainer(config.Value.DatabaseName, UserContainerName);
                var userStore = new CosmosUserStore(container);
                return userStore;
            });

            return services;
        }
    }
}
