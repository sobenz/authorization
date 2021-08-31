using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.ServerTestApp
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(opts =>
            {
                opts.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                opts.DefaultChallengeScheme = "sobenz-auth";
            })
            .AddCookie(opts =>
            {
                opts.Cookie.Name = "SobenzSessionCookie";
                opts.SlidingExpiration = true;
                opts.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                opts.Events.OnValidatePrincipal = (ctx) =>
                {
                    return Task.CompletedTask;
                };
            })
            //.AddOAuth("sobenz-auth", opts =>
            //{
            //    opts.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    opts.ClientId = "00000000-0000-0000-0000-000000000001";
            //    opts.ClientSecret = "booyah";
            //    opts.UsePkce = true;
            //    opts.ReturnUrlParameter = "redirect_uri";
            //    opts.CallbackPath = "/verify_auth_code";
            //    opts.AuthorizationEndpoint = "https://localhost:44311/authorize";
            //    opts.TokenEndpoint = "https://localhost:44311/api/token";
            //    opts.Scope.Add("merchant");
            //    opts.SaveTokens = true;
            //});
            .AddOpenIdConnect("sobenz-auth", opts =>
            {
                opts.Authority = "https://localhost:44311";
                opts.ResponseType = "code";
                opts.AuthenticationMethod = OpenIdConnectRedirectBehavior.RedirectGet;
                opts.CallbackPath = "/verify_auth_code";
                opts.ClientId = "00000000-0000-0000-0000-000000000001";
                opts.ClientSecret = "booyah";
                //opts.ClientId = "00000000-0000-0000-0000-000000000002";
                opts.UsePkce = true;
                opts.Scope.Add("merchant");
                opts.RequireHttpsMetadata = true;
                opts.TokenValidationParameters.ValidAudience = "00000000-0000-0000-0000-000000000001";
                opts.TokenValidationParameters.ValidIssuer = "https://sobenz.com";
            });

            services.AddAuthorization(options =>
            {
                options.FallbackPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
            });

            services.AddRazorPages();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            var cookiePolicyOptions = new CookiePolicyOptions
            {
                MinimumSameSitePolicy = SameSiteMode.Strict,
                HttpOnly = HttpOnlyPolicy.Always,
                Secure = CookieSecurePolicy.Always,
            };
            app.UseCookiePolicy(cookiePolicyOptions);

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
            });
        }
    }
}
