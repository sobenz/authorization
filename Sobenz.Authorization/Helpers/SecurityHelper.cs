using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;

namespace Sobenz.Authorization.Helpers
{
    internal static class SecurityHelper
    {
        private const string NameIdentiferClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";

        public static AuthorizationOptions AddAuthorizationPolicies(this AuthorizationOptions options)
        {
            options.AddPolicy(PolicyNames.ClientRegistrationPolicy, policy =>
            {
                policy.RequireClaim(CustomClaims.SecurityContext, SecurityContexts.ClientRegistration);
                policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
            });
            options.AddPolicy(PolicyNames.ClientConfigurationPolicy, policy =>
            {
                //Check the user has either the client registration context, or is accessing a client they have permission to access.
                policy.RequireAssertion(context =>
                {
                    var httpContext = context.Resource as HttpContext;
                    string subject = httpContext?.Request.RouteValues.GetValueOrDefault("clientId")?.ToString();

                    return context.User.HasClaim(CustomClaims.SecurityContext, SecurityContexts.ClientRegistration) ||
                        ((!string.IsNullOrWhiteSpace(subject)) && context.User.HasClaim(CustomClaims.SecurityContext, SecurityContexts.ClientConfiguration(subject)));
                });
                policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
            });

            return options;
        }

        public static class PolicyNames
        {
            public const string ClientRegistrationPolicy = "ClientRegistration";
            public const string ClientConfigurationPolicy = "ClientConfiguration";
        }

        public static class SecurityContexts
        {
            public const string ClientRegistration = "urn:security:client-registration";
            public static string ClientConfiguration(string clientId) => $"urn:security:client-configuration:{clientId}";
        }
    }
}
