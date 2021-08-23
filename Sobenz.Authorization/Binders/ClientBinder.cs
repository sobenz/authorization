using Microsoft.AspNetCore.Mvc.ModelBinding;
using System;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Binders
{
    public class ClientBinder : IModelBinder
    {
        public Task BindModelAsync(ModelBindingContext bindingContext)
        {
            try
            {
                string clientId = null;
                string clientSecret = null;
                if (bindingContext.HttpContext.Request.Headers.ContainsKey("Authorization"))
                {
                    var authHeader = AuthenticationHeaderValue.Parse(bindingContext.HttpContext.Request.Headers["Authorization"]);
                    var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
                    var credentials = Encoding.UTF8.GetString(credentialBytes).Split(new[] { ':' }, 2);
                    clientId = credentials[0];
                    clientSecret = credentials[1];
                }
                var noAuthField = bindingContext.ValueProvider.GetValue(bindingContext.FieldName).FirstOrDefault();

                switch (bindingContext.FieldName)
                {
                    case "client_id":
                        if (!string.IsNullOrWhiteSpace(clientId) && !string.IsNullOrWhiteSpace(noAuthField))
                            bindingContext.Result = ModelBindingResult.Failed();
                        else
                        {
                            if (Guid.TryParse(string.IsNullOrEmpty(clientId) ? noAuthField : clientId, out Guid clientIdGuid))
                                bindingContext.Result = ModelBindingResult.Success(clientIdGuid);
                            else
                                bindingContext.Result = ModelBindingResult.Failed();
                        }
                        break;
                    case "client_secret":
                        if (!string.IsNullOrWhiteSpace(clientSecret) && !string.IsNullOrWhiteSpace(noAuthField))
                            bindingContext.Result = ModelBindingResult.Failed();
                        else
                            bindingContext.Result = ModelBindingResult.Success(string.IsNullOrEmpty(clientSecret) ? noAuthField : clientSecret);
                        break;
                    default:
                        bindingContext.Result = ModelBindingResult.Failed();
                        break;
                }
            }
            catch (Exception)
            {
                bindingContext.Result = ModelBindingResult.Failed();
            }

            return Task.CompletedTask;
        }
    }
}
