using System;
using System.Collections.Generic;

namespace Sobenz.Authorization.Common.Models
{
    public abstract class Subject
    {
        public Subject(SubjectType type)
        {
            SubjectType = type;
        }

        public Guid Id { get; init; }
        public SubjectType SubjectType { get; init; }
        public DateTime? Created { get; set; }
        public DateTime? LastModified { get; set; }
        public IEnumerable<string> GlobalRoles { get; set; }
        public IDictionary<int, IEnumerable<string>> ContextualRoles { get; set; }
    }
}
