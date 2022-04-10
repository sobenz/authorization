using System;
using System.Collections.Generic;

namespace Sobenz.Authorization.Common.Models
{
    public enum ClientState
    {
        Active,
        Disabled
    }

    public class Client : Subject
    {
        public Client() : base(SubjectType.Client)
        {
        }

        public string Name { get; set; }
        public IEnumerable<string> Contacts { get; set; }
        public string LogoUrl { get; set; }
        public string RegistrationAccessToken { get; set; }
        public bool IsConfidential { get; set; }
        public ClientState State { get; set; }
        public IEnumerable<string> GrantedScopes { get; set; }
        public IEnumerable<string> UserAccessibleScopes { get; set; }
        public IEnumerable<Uri> RedirectionUrls { get; set; }
        public IEnumerable<ClientSecret> Secrets { get; set; }
    }
}
