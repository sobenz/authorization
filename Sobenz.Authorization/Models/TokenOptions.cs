using System;

namespace Sobenz.Authorization.Models
{
    public class TokenOptions
    {
        public string TokenIssuer { get; set; }
        public TimeSpan UserAccessTokenLifetime { get; set; }
        public TimeSpan ApplicationAccessTokenLifetime { get; set; }
        public TimeSpan IdentityTokenLifetime { get; set; }
        public string ConsumerAccessTokenAudience { get; set; }
        public string MerchantAccessTokenAudience { get; set; }
        public bool BypassExplicitGrantScopes { get; set; }
    }
}
