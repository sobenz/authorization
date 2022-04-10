using Newtonsoft.Json;
using Sobenz.Authorization.Common.Models;
using System;
using System.Collections.Generic;

namespace Sobenz.Authorization.Store.Cosmos.Models
{
    internal class CosmosUserModel
    {
        public Guid Id { get; set; }
        public string Username { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public DateTime? DateOfBirth { get; set; }
        public string EmailAddress { get; set; }
        public bool EmailVerified { get; set; }
        public UserState State { get; set; }
        public DateTime? Created { get; set; }
        [JsonProperty("_ts")]
        public long? LastModifiedTimestamp { get; set; }
        public IEnumerable<string> GlobalRoles { get; set; }
        public IDictionary<int, IEnumerable<string>> ContextualRoles { get; set; }
        public IList<dynamic> Identities { get; set; }

        public static User ToDomainModel(CosmosUserModel cosmosModel)
        {
            if (cosmosModel == null)
                return null;

            var result = new User
            {
                Id = cosmosModel.Id,
                Username = cosmosModel.Username,
                FirstName = cosmosModel.FirstName,
                LastName = cosmosModel.LastName,
                DateOfBirth = cosmosModel.DateOfBirth,
                EmailAddress = cosmosModel.EmailAddress,
                EmailVerified = cosmosModel.EmailVerified,
                State = cosmosModel.State,
                Created = cosmosModel.Created,
                LastModified = cosmosModel.LastModifiedTimestamp.HasValue ? DateTimeOffset.FromUnixTimeSeconds(cosmosModel.LastModifiedTimestamp.Value).UtcDateTime : null,
                GlobalRoles = cosmosModel.GlobalRoles,
                ContextualRoles = cosmosModel.ContextualRoles,
            };
            var identities = new List<UserIdentity>();
            foreach (var identity in cosmosModel.Identities)
            {
                switch((string)identity.identityType)
                {
                    case "Password":
                        var pwdId = new UserPasswordIdentity
                        {
                            CreatedUtc = identity.createdUtc,
                            LastAuthenticateUtc = identity.lastAuthenticateUtc,
                            Password = identity.password,
                            Salt = identity.salt
                        };
                        identities.Add(pwdId);
                        break;
                }
            }
            result.Identities = identities;
            return result;
        }

        public static CosmosUserModel FromDomainModel(User user)
        {
            var result = new CosmosUserModel
            {
                Id = user.Id,
                Username = user.Username,
                FirstName = user.FirstName,
                LastName = user.LastName,
                DateOfBirth = user.DateOfBirth,
                EmailAddress = user.EmailAddress,
                EmailVerified = user.EmailVerified,
                State = user.State,
                GlobalRoles = user.GlobalRoles,
                ContextualRoles = user.ContextualRoles,
                Identities = new List<dynamic>()
            };
            foreach(var identity in user.Identities)
            {
                result.Identities.Add(identity);
            }
            return result;
        }
    }
}
