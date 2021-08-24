﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Sobenz.Authorization.Interfaces;
using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Controllers
{
    [Route("authorize")]
    public class AuthorizeController : Controller
    {
        private readonly IApplicationService _applicationService;
        private readonly IUserService _userService;

        public AuthorizeController(IApplicationService applicationService, IUserService userService)
        {
            _applicationService = applicationService ?? throw new ArgumentNullException(nameof(applicationService));
            _userService = userService ?? throw new ArgumentNullException(nameof(userService));
        }

        [HttpGet]
        public async Task<IActionResult> Index([FromQuery]AuthorizeRequest authorizeRequest, CancellationToken cancellationToken = default)
        {
            if (!ModelState.IsValid)
                return View("error"); //Missing required parameters
            var application = await _applicationService.GetAsync(authorizeRequest.ClientId.Value, cancellationToken);

            if (application == null)
                return View("error"); //Invalid client

            if (!application.IsConfidential && (string.IsNullOrEmpty(authorizeRequest.CodeChallenge) || !authorizeRequest.CodeChallengeMethod.HasValue))
                return View("error"); //Public client without PKCE Code challenge

            if (authorizeRequest.Scopes.Any(scope => !application.AllowedScopes.Contains(scope)))
                return View("error"); //Application not allowed Scopes being requested.

            if (User.Identity.IsAuthenticated)
                return View("grant", authorizeRequest);
            else
                return View("login", authorizeRequest);
        }

        [HttpPost]
        public Task<IActionResult> Login([FromForm]AuthorizeOperation authorizationOperation, [FromQuery]AuthorizeRequest authorizeRequest, CancellationToken cancellationToken = default)
        {
            switch(authorizationOperation.Action)
            {
                case AuthorizeOperationType.Login:
                    return ProcessLoginAsync(authorizationOperation.Username, authorizationOperation.Password, authorizeRequest, cancellationToken);
                case AuthorizeOperationType.Grant:
                    return ProcessGrantAsync(authorizeRequest, cancellationToken);
                default:
                    return ProcessLogoutAsync(authorizeRequest, cancellationToken);
            }
        }

        private async Task<IActionResult> ProcessGrantAsync(AuthorizeRequest authorizeRequest, CancellationToken cancellationToken)
        {
            //TODO Generate Access Code & Redirect
            return await Task.FromResult<IActionResult>(View("login", authorizeRequest));
        }

        private async Task<IActionResult> ProcessLoginAsync(string username, string password, AuthorizeRequest authorizeRequest, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                return View("login", authorizeRequest);

            var user = await _userService.AuthenticateWithPasswordAsync(username, password, cancellationToken);
            if (user == null)
                return View("login", authorizeRequest); //Failed Login

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Sid, user.Id.ToString()),
                new Claim(ClaimTypes.Name, username),
                new Claim("FullName", $"{user.FirstName} {user.LastName}")
            };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties
            {
                AllowRefresh = true,
                ExpiresUtc = DateTime.Now.AddMinutes(10),
                IsPersistent = true,
                IssuedUtc = DateTime.UtcNow
            };

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);
            return View("grant", authorizeRequest);
        }

        private async Task<IActionResult> ProcessLogoutAsync(AuthorizeRequest authorizeRequest, CancellationToken cancellationToken)
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return View("login", authorizeRequest);
        }
    }
}