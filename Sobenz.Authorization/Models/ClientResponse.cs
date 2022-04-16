using Sobenz.Authorization.Common.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace Sobenz.Authorization.Models
{
    public class ClientResponse
    {
        public ClientResponse(Client client, string secret, string registrationUrl)
        {
            ClientId = client.Id;
            ClientSecret = secret;
            ClientSecretExpiresAt = (long)(client.Secrets.FirstOrDefault()?.ActiveTo.Subtract(new DateTime(1970, 1, 1)).TotalSeconds ?? 0);
            RegistrationAccessToken = client.RegistrationAccessToken;
            RegistrationClientUri = registrationUrl;
            ApplicationType = client.IsConfidential ? ApplicationType.Native : ApplicationType.Web;
            RedirectionUris = client.RedirectionUrls.Select(u => u.ToString());
            ClientName = client.Name;
            LogoUri = client.LogoUrl;
            Contacts = client.Contacts;
            GrantedScopes = string.Join(' ', client.GrantedScopes);
            UserAccessibleScopes = string.Join(' ', client.UserAccessibleScopes);
        }

        [JsonPropertyName("client_id")]
        public Guid ClientId { get; init; }

        [JsonPropertyName("client_secret")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string ClientSecret { get; init; }

        [JsonPropertyName("client_secret_expires_at")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public long ClientSecretExpiresAt { get; init; }

        [JsonPropertyName("registration_access_token")]
        public string RegistrationAccessToken { get; init; }

        [JsonPropertyName("registration_client_uri")]
        public string RegistrationClientUri { get; init; }

        [JsonPropertyName("token_endpoint_auth_method")]
        public string TokenEndpointAuthMethod { get; } = "client_secret_post client_secret_basic";

        [JsonPropertyName("application_type")]
        public ApplicationType ApplicationType { get; init; }

        [JsonPropertyName("redirection_uris")]
        public IEnumerable<string> RedirectionUris { get; init; }

        [JsonPropertyName("client_name")]
        public string  ClientName { get; init; }

        [JsonPropertyName("logo_uri")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string LogoUri { get; init; }

        [JsonPropertyName("contacts")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public IEnumerable<string> Contacts { get; init; }

        [JsonPropertyName("granted_scopes")]
        public string GrantedScopes { get; init; }

        [JsonPropertyName("user_accessible_scopes")]
        public string UserAccessibleScopes { get; init; }
    }
}
