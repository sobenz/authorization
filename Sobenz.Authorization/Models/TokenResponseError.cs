using Sobenz.Authorization.Interfaces;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Sobenz.Authorization.Models
{
    [JsonConverter(typeof(JsonStringEnumMemberConverter))]
    public enum TokenFailureError
    {
        [EnumMember(Value = "access_denied")]
        AccessDenied,

        [EnumMember(Value = "invalid_client")]
        InvalidClient,

        [EnumMember(Value = "invalid_grant")]
        InvalidGrant,

        [EnumMember(Value = "invalid_scope")]
        InvalidScope,

        [EnumMember(Value = "invalid_token")]
        InvalidToken,

        [EnumMember(Value = "unauthorized_client")]
        UnauthorizedClient
    }

    public class TokenResponseError : ITokenResponse
    {
        [JsonPropertyName("error")]
        public TokenFailureError Error { get; set; }

        [JsonPropertyName("error_description")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string ErrorDescription { get; set; }

        [JsonPropertyName("error_uri")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string ErrorUri { get; set; }
    }
}
