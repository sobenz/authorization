using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Sobenz.Authorization.Models
{
    public class ClientResponse
    {
        [JsonPropertyName("client_id")]
        public Guid ClientId { get; set; }

        [JsonPropertyName("client_secret")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string ClientSecret { get; set; }

        [JsonPropertyName("client_secret_expires_at")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public long ClientSecretExpiresAt { get; set; }

        [JsonPropertyName("registration_access_token")]
        public string RegistrationAccessToken { get; set; }

        [JsonPropertyName("registration_client_uri")]
        public string RegistrationClientUri { get; set; }

        [JsonPropertyName("token_endpoint_auth_method")]
        public string TokenEndpointAuthMethod { get; } = "client_secret_post client_secret_basic";

        [JsonPropertyName("application_type")]
        public ApplicationType ApplicationType { get; set; }

        [JsonPropertyName("redirection_uris")]
        public IEnumerable<string> RedirectionUris { get; set; }

        [JsonPropertyName("client_name")]
        public string  ClientName { get; set; }

        [JsonPropertyName("logo_uri")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string LogoUri { get; set; }

        [JsonPropertyName("contacts")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public IEnumerable<string> Contacts { get; set; }

        [JsonPropertyName("granted_scopes")]
        public string GrantedScopes { get; set; }

        [JsonPropertyName("user_accessible_scopes")]
        public string UserAccessibleScopes { get; set; }
    }
}
