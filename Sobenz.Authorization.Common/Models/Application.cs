﻿using System;
using System.Collections.Generic;

namespace Sobenz.Authorization.Common.Models
{
    public enum ApplicationState
    {
        Active,
        Disabled
    }

    public class Application : Subject
    {
        public Application() : base(SubjectType.Application)
        {
        }

        public string Name { get; set; }
        public IEnumerable<string> Contacts { get; set; }
        public string LogoUri { get; set; }
        public string RegistrationAccessToken { get; set; }
        public bool IsConfidential { get; set; }
        public ApplicationState State { get; set; }
        public IEnumerable<string> GrantedScopes { get; set; }
        public IEnumerable<string> UserAccessibleScopes { get; set; }
        public IEnumerable<Uri> RedirectionUrls { get; set; }
        public IEnumerable<ClientSecret> Secrets { get; set; }
    }
}
