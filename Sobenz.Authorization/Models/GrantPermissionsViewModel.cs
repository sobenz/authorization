using System;

namespace Sobenz.Authorization.Models
{
    public class GrantPermissionsViewModel
    {
        public AuthorizeRequest AuthorizationRequest { get; set; }
        public Application RequestingApplication { get; set; }
    }
}
