using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Sobenz.Authorization.Models
{
    public class Jwks
    {
        public Jwks()
        {
            Keys = new List<Jwk>();
        }

        [JsonPropertyName("keys")]
        public ICollection<Jwk> Keys { get; set; }
    }

    public class Jwk
    {
        [JsonPropertyName("kty")]
        public string KeyType { get; set; }
        [JsonPropertyName("use")]
        public string PublicKeyUse { get; set; }
        [JsonPropertyName("kid")]
        public string KeyId { get; set; }
        [JsonPropertyName("alg")]
        public string Algorithm { get; set; }
        [JsonPropertyName("e")]
        public string E { get; set; }
        [JsonPropertyName("n")]
        public string N { get; set; }
    }
}
