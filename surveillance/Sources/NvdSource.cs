using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Vigie.Scanner.Models;
using Vigie.Shared;

namespace Vigie.Scanner.Sources;

/// <summary>
/// NVD (NIST) API 2.0 — https://nvd.nist.gov/developers/vulnerabilities
///  - produit connu (CPE) : virtualMatchString=cpe:2.3:a:vendeur:produit (toutes versions, filtrage local)
///  - produit inconnu     : keywordSearch=nom (corrélation "probable")
///  - scans suivants      : lastModStartDate / lastModEndDate (fenêtres de 120 jours max imposées par le NVD)
/// Limite : 5 requêtes / 30 s sans clé, 50 / 30 s avec clé.
/// </summary>
public sealed class NvdSource(HttpClient http, IOptionsMonitor<SourcesOptions> options) : ITechnologySource
{
    private static readonly SemaphoreSlim RateGate = new(1, 1);
    private static DateTime _lastCall = DateTime.MinValue;
    private const int PageSize = 2000;

    public string Name => "NVD";
    public bool Enabled => options.CurrentValue.Nvd.Enabled;
    private NvdOptions O => options.CurrentValue.Nvd;

    public async Task<IReadOnlyList<NormalizedVulnerability>> FetchAsync(ScanTechnology tech, DateTime? since, ScanLog log, CancellationToken ct)
    {
        string filter;
        if (!string.IsNullOrEmpty(tech.Vendor))
        {
            var part = CpeName.Parse(tech.Cpe)?.Part ?? (tech.Type == TechTypes.Os ? "o" : "a");
            filter = "virtualMatchString=" + Uri.EscapeDataString(CpeName.MatchString(part, tech.Vendor, tech.Product));
        }
        else if (string.IsNullOrEmpty(tech.Ecosystem))
        {
            var kw = tech.Name.Replace("(image Docker)", "").Split(':')[0].Trim();
            filter = "keywordSearch=" + Uri.EscapeDataString(kw) + "&keywordExactMatch";
        }
        else
        {
            return []; // paquet sans CPE connue : OSV est la source fiable
        }

        var windows = new List<(DateTime? From, DateTime? To)>();
        if (since is null) windows.Add((null, null));
        else
        {
            var end = DateTime.UtcNow;
            var start = since.Value;
            while (start < end)
            {
                var wEnd = start.AddDays(119) < end ? start.AddDays(119) : end;
                windows.Add((start, wEnd));
                start = wEnd;
            }
        }

        var results = new List<NormalizedVulnerability>();
        foreach (var (from, to) in windows)
        {
            var startIndex = 0;
            while (true)
            {
                var url = $"{O.BaseUrl}?{filter}&resultsPerPage={PageSize}&startIndex={startIndex}";
                if (from is not null)
                    url += $"&lastModStartDate={NvdDate(from.Value)}&lastModEndDate={NvdDate(to!.Value)}";

                using var doc = await GetAsync(url, ct);
                if (doc is null) break;
                var root = doc.RootElement;
                foreach (var item in root.Arr("vulnerabilities"))
                    if (item.Prop("cve") is { } cve) results.Add(Parse(cve));

                var total = (int)(root.Dec("totalResults") ?? 0);
                startIndex += PageSize;
                if (startIndex >= total) break;
            }
        }

        log.Info($"NVD : {results.Count} CVE pour {tech.Label}{(since is null ? " (inventaire complet)" : $" (modifiées depuis {since:yyyy-MM-dd})")}");
        return results;
    }

    /// <summary>Une CVE précise (utilisé pour les entrées du catalogue KEV absentes de la base).</summary>
    public async Task<NormalizedVulnerability?> GetByCveAsync(string cveId, CancellationToken ct)
    {
        using var doc = await GetAsync($"{O.BaseUrl}?cveId={Uri.EscapeDataString(cveId)}", ct);
        var cve = doc?.RootElement.Arr("vulnerabilities").Select(v => v.Prop("cve")).FirstOrDefault(c => c is not null);
        return cve is { } c2 ? Parse(c2) : null;
    }

    // Format exigé : 2024-01-01T00:00:00.000+00:00 (le + encodé)
    private static string NvdDate(DateTime d) => d.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff") + "%2B00:00";

    private async Task<JsonDocument?> GetAsync(string url, CancellationToken ct)
    {
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            await ThrottleAsync(ct);
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            if (!string.IsNullOrWhiteSpace(O.ApiKey)) req.Headers.Add("apiKey", O.ApiKey);
            using var resp = await http.SendAsync(req, ct);

            if (resp.IsSuccessStatusCode)
            {
                await using var stream = await resp.Content.ReadAsStreamAsync(ct);
                return await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            }
            if (resp.StatusCode == HttpStatusCode.NotFound) return null;
            if (resp.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable
                or HttpStatusCode.BadGateway or HttpStatusCode.GatewayTimeout)
            {
                // 403 = limite de débit dépassée côté NVD
                await Task.Delay(TimeSpan.FromSeconds(10 * attempt), ct);
                continue;
            }
            var body = await resp.Content.ReadAsStringAsync(ct);
            var msg = resp.Headers.TryGetValues("message", out var msgs) ? msgs.FirstOrDefault() : null;
            throw new HttpRequestException($"NVD {(int)resp.StatusCode} : {msg ?? body.Trunc(300)}");
        }
        throw new HttpRequestException("NVD indisponible après 5 tentatives (limite de débit ? ajouter NVD_API_KEY)");
    }

    private async Task ThrottleAsync(CancellationToken ct)
    {
        var minInterval = TimeSpan.FromMilliseconds(string.IsNullOrWhiteSpace(O.ApiKey) ? 6500 : 700);
        await RateGate.WaitAsync(ct);
        try
        {
            var wait = _lastCall + minInterval - DateTime.UtcNow;
            if (wait > TimeSpan.Zero) await Task.Delay(wait, ct);
            _lastCall = DateTime.UtcNow;
        }
        finally { RateGate.Release(); }
    }

    /// <summary>Conversion d'un objet "cve" NVD vers le format pivot.</summary>
    public static NormalizedVulnerability Parse(JsonElement cve)
    {
        var id = cve.Str("id") ?? "";
        var v = new NormalizedVulnerability
        {
            ExternalId = id,
            CveId = id,
            Source = "NVD",
            SourceStatus = cve.Str("vulnStatus"),
            PublishedAt = cve.Date("published"),
            LastModifiedAt = cve.Date("lastModified"),
            Description = cve.Arr("descriptions").FirstOrDefault(d => d.Str("lang") == "en").Str("value"),
        };

        // CVSS : v3.1 > v4.0 > v3.0 > v2 ; source principale (NVD) de préférence
        if (cve.Prop("metrics") is { } metrics)
        {
            foreach (var key in new[] { "cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2" })
            {
                var list = metrics.Arr(key).ToList();
                if (list.Count == 0) continue;
                var m = list.FirstOrDefault(x => x.Str("type") == "Primary");
                if (m.ValueKind == JsonValueKind.Undefined) m = list[0];
                if (m.Prop("cvssData") is not { } data) continue;
                v.CvssScore = data.Dec("baseScore");
                v.CvssVector = data.Str("vectorString");
                v.CvssVersion = data.Str("version");
                v.Severity = Severity.Normalize(data.Str("baseSeverity") ?? m.Str("baseSeverity"));
                if (v.Severity == Severity.Unknown) v.Severity = Severity.FromCvss(v.CvssScore);
                break;
            }
        }

        v.Cwe = string.Join(", ", cve.Arr("weaknesses").SelectMany(w => w.Arr("description"))
            .Select(d => d.Str("value")).Where(s => s is not null && s.StartsWith("CWE-")).Distinct()).Trunc(200);
        if (v.Cwe.Length == 0) v.Cwe = null;

        // Configurations -> règles CPE vulnérables
        foreach (var node in cve.Arr("configurations").SelectMany(c => c.Arr("nodes")))
        {
            if (node.Bool("negate")) continue;
            foreach (var match in node.Arr("cpeMatch"))
            {
                if (!match.Bool("vulnerable")) continue;
                var cpe = CpeName.Parse(match.Str("criteria"));
                if (cpe is null) continue;
                v.Affected.Add(new AffectedRule
                {
                    Kind = "cpe", Source = "NVD", Part = cpe.Part, Vendor = cpe.Vendor, Product = cpe.Product,
                    Version = VersionComparer.IsWildcard(cpe.Version) ? null : cpe.Version,
                    StartIncluding = match.Str("versionStartIncluding"),
                    StartExcluding = match.Str("versionStartExcluding"),
                    EndIncluding = match.Str("versionEndIncluding"),
                    EndExcluding = match.Str("versionEndExcluding"),
                });
            }
        }

        v.References = cve.Arr("references").Select(r => new ReferenceLink(r.Str("url") ?? "", r.Arr("tags").Select(t => t.GetString() ?? "").ToList()))
            .Where(r => r.Url.Length > 0).Take(40).ToList();

        // Le NVD recopie aussi les champs CISA KEV
        if (cve.Str("cisaExploitAdd") is not null)
        {
            v.InKev = true;
            v.KevDateAdded = cve.Date("cisaExploitAdd");
            v.KevDueDate = cve.Date("cisaActionDue");
            v.KevRequiredAction = cve.Str("cisaRequiredAction");
            v.Title = cve.Str("cisaVulnerabilityName");
        }
        v.Title ??= JsonExt.TitleFrom(v.Description);
        return v;
    }
}
