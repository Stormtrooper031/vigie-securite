using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using Vigie.Api.Models;

namespace Vigie.Api.Services;

/// <summary>Protège les routes internes (scanner -> backend) par l'en-tête X-Api-Key.</summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class InternalApiKeyAttribute : Attribute, IAsyncActionFilter
{
    public const string HeaderName = "X-Api-Key";

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var expected = context.HttpContext.RequestServices.GetRequiredService<IOptions<SecurityOptions>>().Value.InternalApiKey;
        var provided = context.HttpContext.Request.Headers[HeaderName].ToString();

        if (string.IsNullOrEmpty(expected) || !FixedEquals(expected, provided))
        {
            context.Result = new UnauthorizedObjectResult(new { error = "Clé d'API interne invalide" });
            return;
        }
        await next();
    }

    private static bool FixedEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}
