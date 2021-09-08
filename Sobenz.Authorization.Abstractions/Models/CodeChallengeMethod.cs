using System.Runtime.Serialization;

namespace Sobenz.Authorization.Abstractions.Models
{
    public enum CodeChallengeMethod
    {
        [EnumMember(Value = "S256")]
        SHA256,

        [EnumMember(Value = "plain")]
        Plain
    }
}
