using System.Net.Http.Json;
using Microsoft.Extensions.Options;
using Vigie.Scanner.Models;

namespace Vigie.Scanner.Services;

/// <summary>Déclenche la création des alertes (et les courriels) côté backend.</summary>
public sealed class BackendClient(HttpClient http, IOptions<SecurityOptions> security, ILogger<BackendClient> logger)
{
    public async Task<int> IngestAsync(int scanRunId, List<AlertIngestItem> items, CancellationToken ct)
    {
        if (items.Count == 0) return 0;
        var created = 0;
        foreach (var chunk in items.Chunk(500))
        {
            for (var attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Post, "/api/alerts/ingest")
                    {
                        Content = JsonContent.Create(new { scanRunId, items = chunk })
                    };
                    req.Headers.Add("X-Api-Key", security.Value.InternalApiKey);
                    using var resp = await http.SendAsync(req, ct);
                    resp.EnsureSuccessStatusCode();
                    var result = await resp.Content.ReadFromJsonAsync<IngestResult>(cancellationToken: ct);
                    created += result?.Created ?? 0;
                    break;
                }
                catch (Exception ex) when (attempt < 3 && ex is not OperationCanceledException)
                {
                    logger.LogWarning("Backend indisponible ({Attempt}/3) : {Message}", attempt, ex.Message);
                    await Task.Delay(TimeSpan.FromSeconds(5 * attempt), ct);
                }
            }
        }
        return created;
    }

    /// <summary>Demande l'envoi du courriel de résumé des alertes en attente.</summary>
    public async Task NotifyAsync(CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/alerts/notify");
        req.Headers.Add("X-Api-Key", security.Value.InternalApiKey);
        using var resp = await http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
    }

    private sealed class IngestResult
    {
        public int Created { get; set; }
    }
}
