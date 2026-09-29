using System.Text.Json;
using Microsoft.Extensions.Options;
using Vigie.Scanner.Models;
using Vigie.Shared;

namespace Vigie.Scanner.Sources;

/// <summary>
/// MITRE CVE Services (enregistrement officiel CVE JSON 5, publié par le CNA).
/// Sert d'enrichissement quand le NVD n'a pas encore analysé une CVE (retard d'analyse NVD) :
/// score CVSS du CNA ou de CISA-ADP, produits/versions affectés, titre.
/// https://cveawg.mitre.org/api/cve/{CVE-ID}
/// </summary>
public sealed class MitreSource(HttpClient http, IOptionsMonitor<SourcesOptions> options)
{
    public bool Enabled => options.CurrentValue.Mitre.Enabled;

    /// <summary>Faut-il enrichir ? (pas de score, ou pas de règle de version)</summary>
    public static bool NeedsEnrichment(NormalizedVulnerability v) =>
        v.CveId is not null && (v.CvssScore is null || v.Affected.All(r => r.Source != "NVD"));

    public async Task<bool> EnrichAsync(NormalizedVulnerability v, CancellationToken ct)
    {
        if (v.CveId is null) return false;
        using var resp = await http.GetAsync(options.CurrentValue.Mitre.BaseUrl.TrimEnd('/') + "/" + v.CveId, ct);
        if (!resp.IsSuccessStatusCode) return false;

        await using var stream = await resp.Content.ReadAsStreamAsync(ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
        var containers = doc.RootElement.Prop("containers");
        var cna = containers?.Prop("cna");
        if (cna is null) return false;

        var changed = false;
        v.Title ??= cna.Value.Str("title");
        if (string.IsNullOrWhiteSpace(v.Description))
        {
            v.Description = cna.Value.Arr("descriptions").FirstOrDefault(d => d.Str("lang")?.StartsWith("en") == true).Str("value");
            changed |= v.Description is not null;
        }

        if (v.CvssScore is null)
        {
            // Métriques du CNA, sinon de CISA-ADP (programme "Vulnrichment")
            var metricSets = new List<JsonElement>(cna.Value.Arr("metrics"));
            if (containers?.Arr("adp") is { } adps) metricSets.AddRange(adps.SelectMany(a => a.Arr("metrics")));
            foreach (var key in new[] { "cvssV3_1", "cvssV4_0", "cvssV3_0" })
            {
                var m = metricSets.Select(ms => ms.Prop(key)).FirstOrDefault(x => x is not null);
                if (m is not { } metric) continue;
                v.CvssScore = metric.Dec("baseScore");
                v.CvssVector = metric.Str("vectorString");
                v.CvssVersion = metric.Str("version");
                v.Severity = Severity.Normalize(metric.Str("baseSeverity"));
                if (v.Severity == Severity.Unknown) v.Severity = Severity.FromCvss(v.CvssScore);
                changed = true;
                break;
            }
        }

        if (v.Affected.All(r => r.Source != "NVD"))
        {
            foreach (var aff in cna.Value.Arr("affected"))
            {
                var vendor = aff.Str("vendor");
                var product = aff.Str("product");
                if (string.IsNullOrWhiteSpace(product) || product.Equals("n/a", StringComparison.OrdinalIgnoreCase)) continue;
                var versions = aff.Arr("versions").ToList();
                if (versions.Count == 0 && aff.Str("defaultStatus") == "affected")
                {
                    v.Affected.Add(new AffectedRule { Kind = "cpe", Source = "MITRE", Vendor = vendor, Product = product });
                    changed = true;
                    continue;
                }
                foreach (var ver in versions)
                {
                    if (ver.Str("status") != "affected" || ver.Str("versionType") == "git") continue;
                    var version = ver.Str("version");
                    var lessThan = ver.Str("lessThan");
                    var lessThanOrEqual = ver.Str("lessThanOrEqual");
                    var rule = new AffectedRule { Kind = "cpe", Source = "MITRE", Vendor = vendor, Product = product };
                    if (lessThan is not null || lessThanOrEqual is not null)
                    {
                        rule.StartIncluding = VersionComparer.IsWildcard(version) ? null : version;
                        rule.EndExcluding = lessThan is "*" ? null : lessThan;
                        rule.EndIncluding = lessThanOrEqual is "*" ? null : lessThanOrEqual;
                    }
                    else rule.Version = version;
                    v.Affected.Add(rule);
                    changed = true;
                }
            }
        }

        if (v.Cwe is null)
        {
            var cwes = cna.Value.Arr("problemTypes").SelectMany(p => p.Arr("descriptions")).Select(d => d.Str("cweId")).Where(c => c is not null).Distinct().ToList();
            if (cwes.Count > 0) v.Cwe = string.Join(", ", cwes).Trunc(200);
        }
        return changed;
    }
}
