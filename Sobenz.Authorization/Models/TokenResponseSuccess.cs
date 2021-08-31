using Sobenz.Authorization.Interfaces;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Sobenz.Authorization.Models
{
    [JsonConverter(typeof(JsonStringEnumMemberConverter))]
    public enum TokenResponseType
    {
        [EnumMember(Value = "access_token")]
        AccessToken,

        [EnumMember(Value = "authorization_code")]
        AuthorizationCode
    }

    public class TokenResponseSuccess : ITokenResponse
    {
        public TokenResponseSuccess(TokenResponseType tokenType, string accessToken, string refreshToken, int expiresIn, IEnumerable<string> scopes, string idToken = null)
        {
            TokenType = tokenType;
            AccessToken = accessToken;
            RefreshToken = refreshToken;
            ExpiresIn = expiresIn;
            Scope = scopes?.Aggregate((s, e) => $"{e} {s}");
            IdentityToken = idToken;
        }

        [JsonPropertyName("access_token")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string AccessToken { get; set; }

        [JsonPropertyName("token_type")]
        public TokenResponseType TokenType { get; set; }

        [JsonPropertyName("expires_in")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public int? ExpiresIn { get; set; }

        [JsonPropertyName("id_token")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string IdentityToken { get; set; }

        [JsonPropertyName("refresh_token")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string RefreshToken { get; set; }

        [JsonPropertyName("scope")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Scope { get; set; }
    }
}
