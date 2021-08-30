using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Sobenz.Authorization.Models;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Controllers
{
    [ApiController]
    public class OpenIdMetadataController : ControllerBase
    {
        [HttpGet]
        [AllowAnonymous]
        [Route(".well-known/openid-configuration")]
        public Task<IActionResult> GetOpenIdMetadataAsync(CancellationToken cancellationToken = default)
        {
            var configuration = new OpenIdConnectConfiguration
            {
                Issuer  = "https://sobenz.com",
                AuthorizationEndpoint = "https://localhost:44311/authorize",
                TokenEndpoint = "https://localhost:44311/api/token",
                //UserInfoEndpoint = "",
                JwksUri = "https://localhost:44311/jwks",
                //RegistrationEndpoint = "",
                //IntrospectionEndpoint = "",
                //EndSessionEndpoint = "",
                RequestParameterSupported = false,
            };
            configuration.GrantTypesSupported.Add("authorization_code");
            configuration.GrantTypesSupported.Add("client_credentials");
            configuration.GrantTypesSupported.Add("password");
            configuration.GrantTypesSupported.Add("refresh_token");


            configuration.ResponseTypesSupported.Add("code");
            configuration.ResponseTypesSupported.Add("token");
            //configuration.ResponseTypesSupported.Add("id_token");
            //configuration.ResponseTypesSupported.Add("id_token token");
            //configuration.ResponseTypesSupported.Add("code id_token");
            //configuration.ResponseTypesSupported.Add("code id_token token");

            configuration.ResponseModesSupported.Add("query");
            configuration.ResponseModesSupported.Add("fragment");

            configuration.SubjectTypesSupported.Add("public");

            configuration.TokenEndpointAuthMethodsSupported.Add("client_secret_basic");
            configuration.TokenEndpointAuthMethodsSupported.Add("client_secret_post");

            configuration.TokenEndpointAuthSigningAlgValuesSupported.Add("RS256");
            configuration.UserInfoEndpointSigningAlgValuesSupported.Add("RS256");
            configuration.IdTokenSigningAlgValuesSupported.Add("RS256");

            configuration.ScopesSupported.Add("openid");
            configuration.ScopesSupported.Add("profile");
            configuration.ScopesSupported.Add("email");
            configuration.ScopesSupported.Add("consumer");
            configuration.ScopesSupported.Add("merchant");


            //Optional
            //
            //configuration.ResponseModesSupported
            //configuration.ClaimsSupported
            JsonSerializerOptions options = new JsonSerializerOptions
            {
                PropertyNamingPolicy = new SnakeCaseNamingPolicy()
            };
            return Task.FromResult<IActionResult>(new JsonResult(configuration, options));
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("jwks")]
        public Task<IActionResult> GetJwksData(CancellationToken cancellationToken = default)
        {
            var cert = new X509Certificate2(@".\Cert\SobenzCert.cer");
            var key = new X509SecurityKey(cert);
            var jwk = JsonWebKeyConverter.ConvertFromX509SecurityKey(key, true);

            var set = new Jwks();
            set.Keys.Add(new Jwk
            {
                Algorithm = jwk.Alg,
                E = jwk.E,
                KeyId = jwk.KeyId,
                KeyType = jwk.Kty,
                N = jwk.N,
                PublicKeyUse = jwk.Use
            });

            return Task.FromResult<IActionResult>(Ok(set));
        }
    }

    public class SnakeCaseNamingPolicy : JsonNamingPolicy
    {
        public static SnakeCaseNamingPolicy Instance { get; } = new SnakeCaseNamingPolicy();

        public override string ConvertName(string name)
        {
            // Conversion to other naming convention goes here. Like SnakeCase, KebabCase etc.
            return name.ToSnakeCase();
        }
    }

    public static class StringUtils
    {
        public static string ToSnakeCase(this string str)
        {
            return string.Concat(str.Select((x, i) => i > 0 && char.IsUpper(x) ? "_" + x.ToString() : x.ToString())).ToLower();
        }
    }
}
