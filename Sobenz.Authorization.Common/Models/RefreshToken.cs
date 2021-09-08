using System;
using System.Collections.Generic;

namespace Sobenz.Authorization.Common.Models
{
    public class RefreshToken : RefreshTokenIdentifier
    {
        public Guid? ClientId { get; set; }
        public int? LastUsedOrganisationContext { get; set; }
        public DateTime? LastRefreshUtc { get; set; }
        public DateTime ExpiresUtc { get; set; }
    }

    public class RefreshTokenIdentifier
    {
        public SubjectType SubjectType { get; set; }
        public Guid Subject { get; set; }
        public string Token { get; set; }
        public IEnumerable<string> Scopes { get; set; }
        public Guid SessionId { get; set; }
    }
}
