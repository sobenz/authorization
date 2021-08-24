using Microsoft.AspNetCore.Mvc;
using Sobenz.Authorization.Binders;
using System.Runtime.Serialization;

namespace Sobenz.Authorization.Models
{
    public enum AuthorizeOperationType
    {
        [EnumMember(Value = "login")]
        Login,
        [EnumMember(Value = "logout")]
        Logout,
        [EnumMember(Value = "grant")]
        Grant
    }

    public class AuthorizeOperation
    {
        [ModelBinder(Name = "action", BinderType = typeof(EnumBinder<AuthorizeOperationType>))]
        public AuthorizeOperationType Action { get; set; }
        [ModelBinder(Name = "username")]
        public string Username { get; set; }
        [ModelBinder(Name = "password")]
        public string Password { get; set; }
    }
}
