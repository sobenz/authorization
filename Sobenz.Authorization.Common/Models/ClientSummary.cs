using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Common.Models
{
    public class ClientSummary
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public ClientState State { get; set; }
        public DateTime Created { get; set; }
        public DateTime LastModified { get; set; }
    }
}
