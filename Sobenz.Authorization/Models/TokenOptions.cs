using System;

namespace Sobenz.Authorization.Models
{
    public class TokenOptions
    {
        public string TokenIssuer { get; set; }
        public TimeSpan UserAccessTokenLifetime { get; set; }
        public TimeSpan ApplicationAccessTokenLifetime { get; set; }
        public TimeSpan IdentityTokenLifetime { get; set; }
        public Uri ConsumerAccessTokenAudience { get; set; }
        public Uri MerchantAccessTokenAudience { get; set; }
        public bool BypassExplicitGrantScopes { get; set; }
    }
}
