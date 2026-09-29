using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Vigie.Scanner.Models;
using Vigie.Shared;

namespace Vigie.Scanner.Sources;

/// <summary>
/// OSV.dev — base agrégée des bulletins de sécurité fournisseurs et écosystèmes :
/// GitHub Security Advisories (npm, NuGet, PyPI, Packagist, Maven, Go...), Debian DSA/DLA,
/// Ubuntu USN, Alpine secdb, RustSec, PyPA, etc.
/// Requête par paquet + version exacte : la réponse ne contient que les failles qui touchent CETTE version.
/// https://google.github.io/osv.dev/post-v1-query/
/// </summary>
public sealed class OsvSource(HttpClient http, IOptionsMonitor<SourcesOptions> options) : ITechnologySource
{
    public string Name => "OSV";
    public bool Enabled => options.CurrentValue.Osv.Enabled;

    public async Task<IReadOnlyList<NormalizedVulnerability>> FetchAsync(ScanTechnology tech, DateTime? since, ScanLog log, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(tech.Ecosystem) || string.IsNullOrEmpty(tech.PackageName)) return [];

        var results = new List<NormalizedVulnerability>();
        string? pageToken = null;
        do
        {
            var body = new Dictionary<string, object?>
            {
                ["package"] = new { name = tech.PackageName, ecosystem = tech.Ecosystem },
            };
            if (!string.IsNullOrWhiteSpace(tech.Version)) body["version"] = tech.Version;
            if (pageToken is not null) body["page_token"] = pageToken;

            using var resp = await http.PostAsJsonAsync(options.CurrentValue.Osv.BaseUrl, body, ct);
            if (!resp.IsSuccessStatusCode)
                throw new HttpRequestException($"OSV {(int)resp.StatusCode} : {(await resp.Content.ReadAsStringAsync(ct)).Trunc(300)}");

            await using var stream = await resp.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            foreach (var vuln in doc.RootElement.Arr("vulns"))
            {
                var v = Parse(vuln);
                v.DirectPackageMatch = !string.IsNullOrWhiteSpace(tech.Version);
                results.Add(v);
            }
            pageToken = doc.RootElement.Str("next_page_token");
        } while (!string.IsNullOrEmpty(pageToken));

        // OSV n'a pas de filtre par date : les scans suivants ne gardent que ce qui a bougé
        if (since is not null) results = results.Where(r => r.LastModifiedAt is null || r.LastModifiedAt >= since).ToList();

        log.Info($"OSV : {results.Count} bulletin(s) pour {tech.Ecosystem}/{tech.PackageName} {tech.Version}");
        return results;
    }

    public static NormalizedVulnerability Parse(JsonElement e)
    {
        var osvId = e.Str("id") ?? "";
        var aliases = e.Arr("aliases").Select(a => a.GetString() ?? "").Where(a => a.Length > 0).ToList();
        var cve = aliases.FirstOrDefault(a => a.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase));

        var v = new NormalizedVulnerability
        {
            ExternalId = cve ?? osvId,
            CveId = cve,
            Source = "OSV",
            Title = e.Str("summary"),
            Description = e.Str("details")?.Trunc(20_000),
            PublishedAt = e.Date("published"),
            LastModifiedAt = e.Date("modified"),
        };
        v.Aliases.Add(osvId);
        foreach (var a in aliases.Where(a => a != cve)) v.Aliases.Add(a);

        // Sévérité : vecteur CVSS v3 (score recalculé) sinon libellé GHSA
        var v3 = e.Arr("severity").FirstOrDefault(s => s.Str("type") == "CVSS_V3");
        if (v3.ValueKind == JsonValueKind.Object)
        {
            v.CvssVector = v3.Str("score");
            v.CvssScore = CvssCalculator.BaseScoreV3(v.CvssVector);
            v.CvssVersion = v.CvssVector?.Split('/')[0].Replace("CVSS:", "");
        }
        else
        {
            var v4 = e.Arr("severity").FirstOrDefault(s => s.Str("type") == "CVSS_V4");
            if (v4.ValueKind == JsonValueKind.Object) { v.CvssVector = v4.Str("score"); v.CvssVersion = "4.0"; }
        }
        var dbSeverity = e.Prop("database_specific")?.Str("severity");
        v.Severity = v.CvssScore is not null ? Severity.FromCvss(v.CvssScore) : Severity.Normalize(dbSeverity);

        var cwes = e.Prop("database_specific") is { } ds ? ds.Arr("cwe_ids").Select(c => c.GetString()).Where(c => c is not null).ToList() : [];
        if (cwes.Count > 0) v.Cwe = string.Join(", ", cwes).Trunc(200);

        foreach (var aff in e.Arr("affected"))
        {
            var pkg = aff.Prop("package");
            var eco = pkg?.Str("ecosystem");
            var name = pkg?.Str("name");
            if (eco is null || name is null) continue;

            var hadRange = false;
            foreach (var range in aff.Arr("ranges"))
            {
                if (range.Str("type") == "GIT") continue;
                string? introduced = null;
                var open = false;
                foreach (var ev in range.Arr("events"))
                {
                    if (ev.Str("introduced") is { } intro) { introduced = intro == "0" ? null : intro; open = true; }
                    else if (ev.Str("fixed") is { } fixedV) { v.Affected.Add(Rule(eco, name, introduced, fixedV, null)); open = false; hadRange = true; }
                    else if (ev.Str("last_affected") is { } last) { v.Affected.Add(Rule(eco, name, introduced, null, last)); open = false; hadRange = true; }
                    else if (ev.Str("limit") is { } limit) { v.Affected.Add(Rule(eco, name, introduced, limit, null)); open = false; hadRange = true; }
                }
                if (open) { v.Affected.Add(Rule(eco, name, introduced, null, null)); hadRange = true; }
            }

            var versions = aff.Arr("versions").Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList();
            if (!hadRange && versions.Count > 0)
                v.Affected.Add(new AffectedRule { Kind = "pkg", Source = "OSV", Ecosystem = eco, Package = name, Versions = versions.Take(300).ToList() });
        }

        v.References = e.Arr("references").Select(r => new ReferenceLink(r.Str("url") ?? "", [r.Str("type") ?? ""]))
            .Where(r => r.Url.Length > 0).Take(40).ToList();
        v.Title ??= JsonExt.TitleFrom(v.Description);
        return v;
    }

    private static AffectedRule Rule(string eco, string name, string? introduced, string? fixedV, string? lastAffected) => new()
    {
        Kind = "pkg", Source = "OSV", Ecosystem = eco, Package = name,
        StartIncluding = introduced, EndExcluding = fixedV, EndIncluding = lastAffected
    };
}
