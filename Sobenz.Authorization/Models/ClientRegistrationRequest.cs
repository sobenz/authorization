using Microsoft.AspNetCore.Mvc;
using Sobenz.Authorization.Binders;
using Sobenz.Authorization.Helpers;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
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

    public class ClientRegistrationRequest : IValidatableObject
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
        public IEnumerable<string> RedirectionUrls { get; set; }

        [JsonPropertyName("logo_uri")]
        [BindProperty(Name = "logo_uri")]
        public string LogoUri { get; set; }

        [JsonPropertyName("contacts")]
        [BindProperty(Name = "contacts")]
        public IEnumerable<string> Contacts { get; set; }

        [JsonPropertyName("granted_scope")]
        [JsonConverter(typeof(SpaceDelimitedStringJsonConverter))]
        [BindProperty(Name = "granted_scope", BinderType = typeof(SpaceDelimitedStringArrayBinder))]
        public string[] GrantedScopes { get; set; }

        [JsonPropertyName("user_accessible_scope")]
        [JsonConverter(typeof(SpaceDelimitedStringJsonConverter))]
        [BindProperty(Name = "user_accessible_scope", BinderType = typeof(SpaceDelimitedStringArrayBinder))]
        public string[] UserAccessibleScopes { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            List<ValidationResult> validationErrors = new List<ValidationResult>();
            if (!RedirectionUrls.Any())
            {
                validationErrors.Add(new ValidationResult(Errors.AtLeastOneRedirectionUrlRequired, new[] { nameof(RedirectionUrls) }));
            }
            if (ApplicationType == ApplicationType.Web)
            {
                foreach(var url in RedirectionUrls)
                {
                    var uri = new Uri(url);
                    if (!uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                        validationErrors.Add(new ValidationResult(string.Format(Errors.WebClientRedirectUrlsMustBeHttps, url), new[] { nameof(RedirectionUrls) }));
#if !DEBUG
                    if (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
                        validationErrors.Add(new ValidationResult(string.Format(Errors.WebClientRedirectUrlsMustNotBeLocalhost, url), new[] { nameof(RedirectionUrls) }));
#endif
                }
            }
            return validationErrors;
        }
    }
}
