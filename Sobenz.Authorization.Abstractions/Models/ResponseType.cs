using System.Runtime.Serialization;

namespace Sobenz.Authorization.Abstractions.Models
{
    public enum ResponseType
    {
        [EnumMember(Value = "code")]
        Code
    }
}
