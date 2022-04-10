using Newtonsoft.Json;
using Sobenz.Authorization.Common.Models;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Sobenz.Authorization.Store.Cosmos.Models
{
    internal class CosmosClientModel
    {
        public Guid Id { get; set; }
        [JsonIgnore]
        public DateTime Created { get; set; }
        [JsonIgnore]
        [JsonProperty("_ts")]
        public long LastModifiedTimestamp { get; set; }
        public string Name { get; set; }
        public IEnumerable<string> Contacts { get; set; }
        public string LogoUri { get; set; }
        public string RegistrationAccessToken { get; set; }
        public bool IsConfidential { get; set; }
        public ApplicationState State { get; set; }
        public IEnumerable<string> GrantedScopes { get; set; }
        public IEnumerable<string> UserAccessibleScopes { get; set; }
        public IEnumerable<string> RedirectionUrls { get; set; }
        public IEnumerable<CosmosClientSecret> Secrets { get; set; }
        public IEnumerable<string> GlobalRoles { get; set; }
        public IDictionary<int, IEnumerable<string>> ContextualRoles { get; set; }

        public static Application ToDomainModel(CosmosClientModel cosmosModel)
        {
            if (cosmosModel == null)
                return null;
            var result = new Application
            {
                Id = cosmosModel.Id,
                Name = cosmosModel.Name,
                IsConfidential = cosmosModel.IsConfidential,
                State = cosmosModel.State,
                Created = cosmosModel.Created,
                LastModified = DateTimeOffset.FromUnixTimeSeconds(cosmosModel.LastModifiedTimestamp).UtcDateTime,
                RedirectionUrls = cosmosModel.RedirectionUrls.Select(u => new Uri(u)),
                Contacts = cosmosModel.Contacts,
                LogoUri = cosmosModel.LogoUri,
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

        public static CosmosClientModel FromDomainModel(Application client)
        {
            var result = new CosmosClientModel
            {
                Id = client.Id,
                Name = client.Name,
                IsConfidential = client.IsConfidential,
                LogoUri = client.LogoUri,
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
            return result;
        }
    }

    internal class CosmosClientSecret
    {
        public string Name { get; set; }
        public string SecretHash { get; set; }
        public DateTime ActiveFrom { get; set; }
        public DateTime ActiveTo { get; set; }
    }
}
