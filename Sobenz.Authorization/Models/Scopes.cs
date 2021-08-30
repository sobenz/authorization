using System.Collections.Generic;

namespace Sobenz.Authorization.Models
{
    public static class Scopes
    {
        public const string Consumer = "consumer";
        public const string Merchant = "merchant";
        public const string Identity = "identity";
        public const string OpenId = "openid";
        public const string Profile = "profile";
        public const string Email = "email";

        public static IEnumerable<string> ExplicitGrantScopes = new [] { Identity, OpenId, Profile, Email };
        public static IEnumerable<string> ImplicitGrantScopes = new[] { Consumer, Merchant };
    }
}
