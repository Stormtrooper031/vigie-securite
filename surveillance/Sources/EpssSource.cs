using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Vigie.Scanner.Sources;

/// <summary>
/// FIRST EPSS : probabilité qu'une CVE soit exploitée dans les 30 prochains jours.
/// https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2 (lots de 50)
/// </summary>
public sealed class EpssSource(HttpClient http, IOptionsMonitor<SourcesOptions> options)
{
    public bool Enabled => options.CurrentValue.Epss.Enabled;

    public async Task<Dictionary<string, (decimal Epss, decimal Percentile)>> FetchAsync(IEnumerable<string> cveIds, CancellationToken ct)
    {
        var result = new Dictionary<string, (decimal, decimal)>(StringComparer.OrdinalIgnoreCase);
        foreach (var batch in cveIds.Distinct().Chunk(50))
        {
            var url = $"{options.CurrentValue.Epss.BaseUrl}?cve={string.Join(',', batch)}";
            using var resp = await http.GetAsync(url, ct);
            if (!resp.IsSuccessStatusCode) continue;
            await using var stream = await resp.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            foreach (var d in doc.RootElement.Arr("data"))
            {
                var cve = d.Str("cve");
                var epss = d.Dec("epss");
                var pct = d.Dec("percentile");
                if (cve is not null && epss is not null) result[cve] = (Math.Round(epss.Value, 5), Math.Round(pct ?? 0, 5));
            }
            await Task.Delay(200, ct);
        }
        return result;
    }
}
