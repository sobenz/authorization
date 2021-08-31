using Sobenz.Authorization.Interfaces;
using System;
using System.Net;

namespace Sobenz.Authorization.Models
{
    public class AuthorizationOutcome
    {
        private static readonly AuthorizationOutcome _success = new AuthorizationOutcome(true, HttpStatusCode.OK, null);

        protected AuthorizationOutcome(bool success, HttpStatusCode statusCode, ITokenResponse response)
        {
            Success = success;
            StatusCode = statusCode;
            TokenResponse = response;
        }

        public bool Success { get; init; }
        public ITokenResponse TokenResponse { get; init; }
        public HttpStatusCode StatusCode { get; init; }

        public static AuthorizationOutcome Succeed() => _success;
        public static AuthorizationOutcome Succeed(ITokenResponse response, HttpStatusCode statusCode = HttpStatusCode.OK)
            => new AuthorizationOutcome(true, statusCode, response ?? throw new ArgumentNullException(nameof(response)));
        public static AuthorizationOutcome Fail(ITokenResponse response, HttpStatusCode statusCode)
            => new AuthorizationOutcome(false, statusCode, response ?? throw new ArgumentNullException(nameof(response)));

    }


    public class AuthorizationOutcome<TResource> : AuthorizationOutcome
    {
        private AuthorizationOutcome(bool success, HttpStatusCode statusCode, ITokenResponse response, TResource resource)
            : base(success, statusCode, response)
        {
            Resource = resource;
        }
        public TResource Resource { get; init; }

        public static new AuthorizationOutcome<TResource> Fail(ITokenResponse response, HttpStatusCode statusCode)
            => new AuthorizationOutcome<TResource>(false, statusCode, response ?? throw new ArgumentNullException(nameof(response)), default);

        public static AuthorizationOutcome<TResource> Succeed(TResource resource, HttpStatusCode statusCode = HttpStatusCode.OK)
            => new AuthorizationOutcome<TResource>(true, statusCode, null, resource ?? throw new ArgumentNullException(nameof(resource)));

        public static new AuthorizationOutcome<TResource> Succeed(ITokenResponse response, HttpStatusCode statusCode = HttpStatusCode.OK)
            => new AuthorizationOutcome<TResource>(true, statusCode, response ?? throw new ArgumentNullException(nameof(response)), default);
    }
}
