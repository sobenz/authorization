using Microsoft.AspNetCore.Mvc;
using Sobenz.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Helpers
{
    internal static class CustomModelValidationErrorBuilder
    {
        public static BadRequestObjectResult BuildCustomError(ActionContext context)
        {
            if (context.RouteData.Values["controller"].ToString() == "Token")
            {
                var errors = context.ModelState.Values.SelectMany(entry => entry.Errors).Select(e => e.ErrorMessage);
                return new BadRequestObjectResult(new TokenResponseError
                {
                    Error = TokenFailureError.InvalidRequest,
                    ErrorDescription = string.Join(", ", errors)
                });
            }
            return new BadRequestObjectResult(context.ModelState);
        }
    }
}
