using Sobenz.Authorization.Common.Models;
using System;

namespace Sobenz.Authorization.Models
{
    public class GrantPermissionsViewModel
    {
        public AuthorizeRequest AuthorizationRequest { get; set; }
        public Client RequestingApplication { get; set; }
    }
}
