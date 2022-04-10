using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Common.Models
{
    public class ApplicationSummary
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public ApplicationState State { get; set; }
        public DateTime Created { get; set; }
        public DateTime LastModified { get; set; }
    }
}
