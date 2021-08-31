using System;
using System.Collections.Generic;

namespace Sobenz.Authorization.Models
{
    public enum UserState
    {
        Active,
        Deactivated
    }

    public class User : Subject
    {
        public User() : base(SubjectType.User)
        {
        }

        public UserState State { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string EmailAddress { get; set; }
        public bool EmailVerified { get; set; }
        public DateTime DateOfBirth { get; set; }
        public IEnumerable<UserIdentity> Identities { get; set; }
    }
}
