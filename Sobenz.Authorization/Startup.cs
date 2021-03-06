using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Sobenz.Authorization.Common;
using Sobenz.Authorization.Common.Interfaces;
using Sobenz.Authorization.Helpers;
using Sobenz.Authorization.Interfaces;
using Sobenz.Authorization.Models;
using Sobenz.Authorization.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace Sobenz.Authorization
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            //Configuration
            services.Configure<TokenOptions>(Configuration.GetSection("TokenSettings"));
            services.Configure<PersistedTokenOptions>(Configuration.GetSection("PersistedTokenSettings"));

            //Persistance
            services.AddCosmosIdentityStore(Configuration);

            //Services
            services.AddSingleton<IPasswordHasher, Argon2PasswordHasher>();
            services.AddSingleton<IClientManager, IClientManager>();
            services.AddSingleton<ITokenProvider, JwtTokenProvider>();
            services.AddSingleton<IAuthorizationManager, AuthorizationManager>();
            services.AddSingleton<PersistedTokenService>();
            services.AddSingleton<IRefreshTokenService>(x => x.GetRequiredService<PersistedTokenService>());
            services.AddSingleton<IAuthorizationCodeService>(x => x.GetRequiredService<PersistedTokenService>());

            //Security
            TokenOptions tokenOptions = Configuration.GetSection("TokenSettings").Get<TokenOptions>();
            services.AddAuthorization(options => options.AddAuthorizationPolicies());
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(opts =>
                {
                    var cert = new X509Certificate2(@".\Cert\SobenzCert.cer");
                    opts.TokenValidationParameters.IssuerSigningKey = new X509SecurityKey(cert);
                    opts.TokenValidationParameters.ValidIssuer = tokenOptions.TokenIssuer;
                    opts.TokenValidationParameters.ValidAudience = tokenOptions.MerchantAccessTokenAudience;
                })
                .AddCookie();

            //Mvc
            services.AddControllersWithViews()
                .ConfigureApiBehaviorOptions(opts => opts.InvalidModelStateResponseFactory = actionContext 
                    => CustomModelValidationErrorBuilder.BuildCustomError(actionContext))
                .AddJsonOptions(opts =>
                {
                    opts.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
#if DEBUG
                    opts.JsonSerializerOptions.WriteIndented = true;
#endif
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
