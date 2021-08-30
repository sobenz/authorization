using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Sobenz.ServerTestApp.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly IAuthenticationService _authenticationService;

        public IndexModel(ILogger<IndexModel> logger, IAuthenticationService authenticationService)
        {
            _authenticationService = authenticationService;
            _logger = logger;
        }

        public void OnGet()
        {
            var res = _authenticationService.AuthenticateAsync(HttpContext, null).Result;
            List<AuthenticationToken> tokens = new List<AuthenticationToken>
            {
                new AuthenticationToken { Name = "access_token", Value = "foo" },
                new AuthenticationToken { Name = "refresh_token", Value = "bar" },
            };
            res.Properties.StoreTokens(tokens);
        }
    }
}
