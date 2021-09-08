using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sobenz.Authorization.Common.Models
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

        public string Username { get; set; }
        public UserState State { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string EmailAddress { get; set; }
        public bool EmailVerified { get; set; }
        public DateTime DateOfBirth { get; set; }

        [JsonConverter(typeof(IdentityConverter))]
        public IEnumerable<UserIdentity> Identities { get; set; }
    }

    public class IdentityConverter : JsonConverter<UserIdentity>
    {
        public override bool CanConvert(Type typeToConvert)
        {
            throw new NotImplementedException();
        }

        public override UserIdentity Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            throw new NotImplementedException();
        }

        public override void Write(Utf8JsonWriter writer, UserIdentity value, JsonSerializerOptions options)
        {
            throw new NotImplementedException();
        }
    }
}
