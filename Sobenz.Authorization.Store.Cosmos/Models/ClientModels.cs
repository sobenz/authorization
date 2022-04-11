using Newtonsoft.Json;
using Sobenz.Authorization.Common.Models;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Sobenz.Authorization.Store.Cosmos.Models
{
    internal static class ClientModel
    {
        public static Client ToDomainModel(ReadClientModel cosmosModel)
        {
            if (cosmosModel == null)
                return null;
            var result = new Client
            {
                Id = cosmosModel.Id,
                Name = cosmosModel.Name,
                IsConfidential = cosmosModel.IsConfidential,
                State = cosmosModel.State,
                Created = cosmosModel.Created,
                LastModified = DateTimeOffset.FromUnixTimeSeconds(cosmosModel.LastModifiedTimestamp).UtcDateTime,
                RedirectionUrls = cosmosModel.RedirectionUrls.Select(u => new Uri(u)),
                Contacts = cosmosModel.Contacts,
                LogoUrl = cosmosModel.LogoUri,
                RegistrationAccessToken = cosmosModel.RegistrationAccessToken,
                GrantedScopes = cosmosModel.GrantedScopes,
                UserAccessibleScopes = cosmosModel.UserAccessibleScopes,
                GlobalRoles = cosmosModel.GlobalRoles,
                ContextualRoles = cosmosModel.ContextualRoles,
                Secrets = cosmosModel.Secrets.Select(s => new ClientSecret
                {
                    Name = s.Name,
                    SecretHash = s.SecretHash,
                    ActiveFrom = s.ActiveFrom,
                    ActiveTo = s.ActiveTo
                })
            };
            return result;
        }

        public static TCosmosModel FromDomainModel<TCosmosModel>(Client client) where TCosmosModel : CoreClientModel, new()
        {
            var result = new TCosmosModel
            {
                Id = client.Id,
                Name = client.Name,
                LogoUri = client.LogoUrl,
                RedirectionUrls = client.RedirectionUrls.Select(u => u.ToString()),
                Contacts = client.Contacts,
                State = client.State,
                RegistrationAccessToken = client.RegistrationAccessToken,
                GrantedScopes = client.GrantedScopes,
                UserAccessibleScopes = client.UserAccessibleScopes,
                GlobalRoles = client.GlobalRoles,
                ContextualRoles = client.ContextualRoles,
                Secrets = client.Secrets.Select(s => new CosmosClientSecret
                {
                    Name = s.Name,
                    SecretHash = s.SecretHash,
                    ActiveFrom = s.ActiveFrom,
                    ActiveTo = s.ActiveTo
                })
            };

            CreateClientModel createModel = result as CreateClientModel;
            if (createModel != null)
            {
                createModel.IsConfidential = client.IsConfidential;
                createModel.Created = DateTime.UtcNow;
            }

            return result;
        }
    }

    internal class CoreClientModel
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public IEnumerable<string> Contacts { get; set; }
        public string LogoUri { get; set; }
        public string RegistrationAccessToken { get; set; }
        public ClientState State { get; set; }
        public IEnumerable<string> GrantedScopes { get; set; }
        public IEnumerable<string> UserAccessibleScopes { get; set; }
        public IEnumerable<string> RedirectionUrls { get; set; }
        public IEnumerable<CosmosClientSecret> Secrets { get; set; }
        public IEnumerable<string> GlobalRoles { get; set; }
        public IDictionary<int, IEnumerable<string>> ContextualRoles { get; set; }
    }

    internal class CreateClientModel : CoreClientModel
    {
        public DateTime Created { get; set; }
        public bool IsConfidential { get; set; }
    }

    internal class ReadClientModel : CreateClientModel
    {
        [JsonProperty("_ts")]
        public long LastModifiedTimestamp { get; set; }
    }

    internal class CosmosClientSecret
    {
        public string Name { get; set; }
        public string SecretHash { get; set; }
        public DateTime ActiveFrom { get; set; }
        public DateTime ActiveTo { get; set; }
    }
}
