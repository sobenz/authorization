using Sobenz.Authorization.Interfaces;
using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Services
{
    internal sealed class ApplicationService : IApplicationService
    {
        private static SHA256 _hasher = SHA256.Create();
        private readonly List<Application> _applications = new List<Application>
        {
            new Application
            {
                ClientId = Guid.Parse("00000000-0000-0000-0000-000000000001"),
                Name = "Admin Service",
                IsConfidential = true,
                AllowedScopes = new [] { Scopes.Merchant },
                State = ApplicationState.Active,
                GlobalRoles = new [] { Roles.SecurityManager },
                ContextualRoles = new Dictionary<int, IEnumerable<string>>
                {
                    { 1, new [] { "StoreManager", "StoreOperator" } }
                },
                Secrets = new []
                {
                    new ClientSecret {
                        Name = "Admin Secret1",
                        ActiveFrom = DateTime.UtcNow.Subtract(TimeSpan.FromDays(7)),
                        ActiveTo = DateTime.UtcNow.AddDays(7),
                        SecretHash = "w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI="
                    },
                    new ClientSecret {
                        Name = "Admin Secret2",
                        ActiveFrom = DateTime.UtcNow.Subtract(TimeSpan.FromDays(1)),
                        ActiveTo = DateTime.UtcNow.AddDays(365),
                        SecretHash = "NI8kxPuV6/Zp9m6MWatkJmtV5nw1wtkbOaOScggeiLA="
                    }
                }
            },
            new Application
            {
                ClientId = Guid.Parse("00000000-0000-0000-0000-000000000002"),
                Name = "Portal Service",
                IsConfidential = false,
                AllowedScopes = new [] { Scopes.Identity },
                State = ApplicationState.Active,
                GlobalRoles = new string[] { },
                ContextualRoles = new Dictionary<int, IEnumerable<string>>(),
                Secrets = new ClientSecret[]
                {
                }
            }
        };

        public Task<Application> AuthenticateAsync(Guid clientId, CancellationToken cancellationToken = default)
        {
            Application result = _applications.FirstOrDefault(a => a.ClientId == clientId && !a.IsConfidential);
            return Task.FromResult(result);
        }

        public Task<Application> AuthenticateAsync(Guid clientId, string clientSecret, CancellationToken cancellationToken = default)
        {
            Application result = null;
            var app = _applications.FirstOrDefault(a => a.ClientId == clientId && a.IsConfidential);
            if (app != null)
            {
                var challenge = Convert.ToBase64String(_hasher.ComputeHash(Encoding.UTF8.GetBytes(clientSecret)));
                if (app.Secrets.Any(s => s.SecretHash == challenge && DateTime.UtcNow > s.ActiveFrom && DateTime.UtcNow < s.ActiveTo))
                {
                    result = app;
                }
            }
            return Task.FromResult(result);
        }

        public Task<Application> GetAsync(Guid clientId, CancellationToken cancellationToken = default)
        {
            Application result = _applications.FirstOrDefault(a => a.ClientId == clientId);
            return Task.FromResult(result);
        }
    }
}
