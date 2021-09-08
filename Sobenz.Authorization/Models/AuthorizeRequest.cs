using Microsoft.AspNetCore.Mvc;
using Sobenz.Authorization.Abstractions.Models;
using Sobenz.Authorization.Binders;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Sobenz.Authorization.Models
{
    public class AuthorizeRequest
    {
        [Required]
        [BindProperty(Name = "response_type", BinderType = typeof(EnumBinder<ResponseType>))]
        [JsonConverter(typeof(JsonStringEnumMemberConverter))]
        public ResponseType? ResponseType { get; set; }

        [Required]
        [BindProperty(Name = "client_id")]
        public Guid? ClientId { get; set; }

        [Required]
        [BindProperty(Name = "redirect_uri")]
        public Uri RedirectUri { get; set; }

        [BindProperty(Name = "state")]
        public string State { get; set; }

        [BindProperty(Name = "scope", BinderType = typeof(SpaceDelimitedStringArrayBinder))]
        public IEnumerable<string> Scopes { get; set; }

        [BindProperty(Name = "code_challenge")]
        public string CodeChallenge { get; set; }

        [BindProperty(Name = "code_challenge_method", BinderType = typeof(EnumBinder<CodeChallengeMethod>))]
        [JsonConverter(typeof(JsonStringEnumMemberConverter))]
        public CodeChallengeMethod? CodeChallengeMethod { get; set; }

        [BindProperty(Name = "nonce")]
        public string Nonce { get; set; }
    }
}
