using System;
using System.Collections.Generic;

namespace Sobenz.Authorization.Models
{
    public enum ApplicationState
    {
        Active,
        Disabled
    }

    public class Application
    {
        public Guid ClientId { get; set; }
        public string Name { get; set; }
        public bool IsConfidential { get; set; }
        public ApplicationState State { get; set; }
        public IEnumerable<string> AllowedScopes { get; set; }
        public IEnumerable<ClientSecret> Secrets { get; set; }
        public IEnumerable<string> GlobalRoles { get; set; }
        public IDictionary<int, IEnumerable<string>> ContextualRoles { get; set; }
    }
}
