using Sobenz.Authorization.Interfaces;
using System;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Sobenz.Authorization.Models
{
    [JsonConverter(typeof(JsonStringEnumMemberConverter))]
    public enum TokenFailureError
    {
        [EnumMember(Value = "access_denied")]
        AccessDenied,

        [EnumMember(Value = "internal_server_error")]
        InternalServerError,

        [EnumMember(Value = "invalid_client")]
        InvalidClient,

        [EnumMember(Value = "invalid_grant")]
        InvalidGrant,

        [EnumMember(Value = "invalid_request")]
        InvalidRequest,

        [EnumMember(Value = "invalid_scope")]
        InvalidScope,

        [EnumMember(Value = "invalid_token")]
        InvalidToken,

        [EnumMember(Value = "unauthorized_client")]
        UnauthorizedClient,

        [EnumMember(Value = "unsupported_grant_type")]
        UnsupportedGrantType
    }

    public class TokenResponseError : ITokenResponse
    {
        public TokenResponseError()
        {
        }

        public TokenResponseError(TokenFailureError error, string description = null, Uri errorUri = null)
        {
            Error = error;
            ErrorDescription = description;
            ErrorUri = errorUri;
        }

        [JsonPropertyName("error")]
        public TokenFailureError Error { get; init; }

        [JsonPropertyName("error_description")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string ErrorDescription { get; init; }

        [JsonPropertyName("error_uri")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Uri ErrorUri { get; init; }
    }
}
