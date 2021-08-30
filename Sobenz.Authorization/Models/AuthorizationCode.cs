using System;
using System.Collections.Generic;

namespace Sobenz.Authorization.Models
{
    public class AuthorizationCode
    {
        public string Code { get; set; }
        public Guid ClientId { get; set; }
        public Guid GrantingUserId { get; set; }
        public IEnumerable<string> GrantedScopes { get; set; }
        public string RedirectionUri { get; set; }
        public string Nonce { get; set; }
        public string CodeChallenge { get; set; }
        public CodeChallengeMethod? CodeChallengeMethod { get; set; }
        public DateTime ExpiresUtc { get; set; }
    }
}
