using Sobenz.Authorization.Common.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Sobenz.Authorization.Interfaces
{
    public interface ITokenProvider
    {
        string GenerateJwtAccessToken(Subject subject, Client client, Guid sessionId, IEnumerable<string> scopes = null, IEnumerable<Claim> additionalClaims = null);
        string GenerateJwtIdentityToken(User subject, Client client, string nonce, IEnumerable<string> scopes = null);
    }
}
