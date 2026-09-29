using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Vigie.Api.Models;

namespace Vigie.Api.Services;

/// <summary>Appels vers le service de surveillance (déclenchement manuel, état).</summary>
public sealed class ScannerClient(HttpClient http, IOptions<SecurityOptions> security, ILogger<ScannerClient> logger)
{
    public async Task<bool> TriggerAsync(int? technologyId)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, technologyId is null ? "/scan" : $"/scan?technologyId={technologyId}");
            req.Headers.Add(InternalApiKeyAttribute.HeaderName, security.Value.InternalApiKey);
            using var resp = await http.SendAsync(req);
            return resp.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            logger.LogWarning("Service de surveillance injoignable : {Message}", ex.Message);
            return false;
        }
    }

    public async Task<JsonElement?> StatusAsync()
    {
        try { return await http.GetFromJsonAsync<JsonElement>("/status"); }
        catch (Exception ex)
        {
            logger.LogWarning("Statut du scanner indisponible : {Message}", ex.Message);
            return null;
        }
    }
}
