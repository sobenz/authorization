using Microsoft.Extensions.Logging;

namespace Sobenz.Authorization.Common
{
    public static class AuthorizationEvents
    {
        public static EventId TokenGenerationFailed => new(1000, name: "TokenGenerationFailed");
    }
}
