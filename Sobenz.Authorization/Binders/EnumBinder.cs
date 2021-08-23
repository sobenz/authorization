using Microsoft.AspNetCore.Mvc.ModelBinding;
using System;
using System.Linq;
using System.Runtime.Serialization;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Binders
{
    public class EnumBinder<TEnum> : IModelBinder
    {
        public Task BindModelAsync(ModelBindingContext bindingContext)
        {
            var stringEnum = bindingContext.ValueProvider.GetValue(bindingContext.FieldName).FirstValue;
            if (!string.IsNullOrEmpty(stringEnum))
            {
                TEnum result = ToEnum(stringEnum);
                bindingContext.Result = ModelBindingResult.Success(result);
            }
            else
            {
                bindingContext.Result = ModelBindingResult.Failed();
            }
            return Task.CompletedTask;
        }

        private static TEnum ToEnum(string str)
        {
            var enumType = typeof(TEnum);
            foreach (var name in Enum.GetNames(enumType))
            {
                var enumMemberAttribute = ((EnumMemberAttribute[])enumType.GetField(name).GetCustomAttributes(typeof(EnumMemberAttribute), true)).SingleOrDefault();
                if (enumMemberAttribute?.Value == str)
                    return (TEnum)Enum.Parse(enumType, name);
            }
            return default(TEnum);
        }
    }
}
