using System;

namespace Sobenz.Authorization.Models
{
    public enum IdentityType
    {
        Password,
        Device,
        External
    }

    public abstract class UserIdentity
    {
        public UserIdentity(IdentityType identityType)
        {
            IdentityType = identityType;
        }

        public IdentityType IdentityType { get; private set; }
        public DateTime CreatedUtc { get; set; }
        public DateTime? LastAuthenticateUtc { get; set; }
    }

    public class UserPasswordIdentity : UserIdentity
    {
        public UserPasswordIdentity() : base(IdentityType.Password)
        {
        }

        public string Username { get; set; }

        public string Password { get; set; }

        public string Salt { get; set; }
    }
}
