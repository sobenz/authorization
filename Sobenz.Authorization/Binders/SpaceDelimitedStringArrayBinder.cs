using Microsoft.AspNetCore.Mvc.ModelBinding;
using System.Linq;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Binders
{
    public class SpaceDelimitedStringArrayBinder : IModelBinder
    {
        public Task BindModelAsync(ModelBindingContext bindingContext)
        {
            var value = bindingContext.ValueProvider.GetValue(bindingContext.FieldName).FirstOrDefault();
            if (value != null)
            {
                var result = value.Split(' ');
                bindingContext.Result = ModelBindingResult.Success(result);
            }
            else
                bindingContext.Result = ModelBindingResult.Failed();
            return Task.CompletedTask;
        }
    }
}
