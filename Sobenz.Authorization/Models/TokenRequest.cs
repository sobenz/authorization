﻿using Microsoft.AspNetCore.Mvc;
using Sobenz.Authorization.Binders;
using Sobenz.Authorization.Helpers;
using System;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Sobenz.Authorization.Models
{
    [JsonConverter(typeof(JsonStringEnumMemberConverter))]
    public enum GrantType
    {
        Unknown,
        [EnumMember(Value = "client_credentials")]
        ClientCredentials
    }

    public class TokenRequest
    {
        [JsonPropertyName("grant_type")]
        [BindProperty(Name = "grant_type", BinderType = typeof(EnumBinder<GrantType>))]
        public GrantType GrantType { get; set; }

        [JsonPropertyName("client_id")]
        [BindProperty(Name = "client_id", BinderType = typeof(ClientBinder))]
        public Guid? ClientId { get; set; }

        [JsonPropertyName("client_secret")]
        [BindProperty(Name = "client_secret", BinderType = typeof(ClientBinder))]
        public string ClientSecret { get; set; }

        [JsonPropertyName("scope")]
        [JsonConverter(typeof(SpaceDelimitedStringJsonConverter))]
        [BindProperty(Name = "scope", BinderType = typeof(SpaceDelimitedStringArrayBinder))]
        public string[] Scopes { get; set; }

        [JsonPropertyName("organisation_id")]
        [BindProperty(Name = "organisation_id")]
        public int? OrganisationId { get; set; }
    }
}
