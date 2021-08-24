using System;
using System.Collections.Generic;

namespace Sobenz.Authorization.Models
{
    public enum UserState
    {
        Active,
        Deactivated
    }

    public class User
    {
        public Guid Id { get; set; }
        public UserState State { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string EmailAddress { get; set; }
        public bool EmailVerified { get; set; }
        public DateTime DateOfBirth { get; set; }
        public IEnumerable<UserIdentity> Identities { get; set; }
        public IEnumerable<string> GlobalRoles { get; set; }
        public IDictionary<int, IEnumerable<string>> ContextualRoles { get; set; }
    }
}
