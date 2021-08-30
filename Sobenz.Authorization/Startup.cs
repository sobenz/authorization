using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Sobenz.Authorization.Interfaces;
using Sobenz.Authorization.Services;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace Sobenz.Authorization
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton<IApplicationService, ApplicationService>();
            services.AddSingleton<IAuthorizationManager, AuthorizationManager>();
            services.AddSingleton<PersistedTokenService>();
            services.AddSingleton<IRefreshTokenService>(x => x.GetRequiredService<PersistedTokenService>());
            services.AddSingleton<IAuthorizationCodeService>(x => x.GetRequiredService<PersistedTokenService>());
            services.AddSingleton<IUserService, UserService>();

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(opts =>
                {
                    var cert = new X509Certificate2(@".\Cert\SobenzCert.cer");
                    opts.TokenValidationParameters.IssuerSigningKey = new X509SecurityKey(cert);
                    opts.TokenValidationParameters.ValidIssuer = "https://sobenz.com";
                    opts.TokenValidationParameters.ValidAudience = "https://api.sobenz.com/merchant";
                })
                .AddCookie();

            services.AddControllersWithViews()
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
