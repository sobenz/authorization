using Microsoft.AspNetCore.Mvc;
using Sobenz.Authorization.Binders;
using Sobenz.Authorization.Helpers;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Sobenz.Authorization.Models
{
    [JsonConverter(typeof(JsonStringEnumMemberConverter))]
    public enum ApplicationType
    {
        [EnumMember(Value = "web")]
        Web,

        [EnumMember(Value = "native")]
        Native
    }

    public class ClientRegistrationRequest
    {
        [Required]
        [JsonPropertyName("client_name")]
        [BindProperty(Name = "client_name")]
        public string ClientName { get; set; }

        [Required]
        [JsonPropertyName("application_type")]
        [BindProperty(Name = "application_type", BinderType = typeof(EnumBinder<ApplicationType>))]
        public ApplicationType ApplicationType { get; set; }

        [Required]
        [JsonPropertyName("redirection_uris")]
        [BindProperty(Name = "redirection_uris")]
        public IEnumerable<string> RedirectionUris { get; set; }

        [JsonPropertyName("logo_uri")]
        [BindProperty(Name = "logo_uri")]
        public string LogoUri { get; set; }

        [JsonPropertyName("contacts")]
        [BindProperty(Name = "contacts")]
        public IEnumerable<string> Contacts { get; set; }

        [JsonPropertyName("allowed_scope")]
        [JsonConverter(typeof(SpaceDelimitedStringJsonConverter))]
        [BindProperty(Name = "allowed_scope", BinderType = typeof(SpaceDelimitedStringArrayBinder))]
        public string[] AllowedScopes { get; set; }
    }
}
