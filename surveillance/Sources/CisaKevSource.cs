using System.Text.Json;
using Microsoft.Extensions.Options;
using Vigie.Scanner.Models;
using Vigie.Shared;

namespace Vigie.Scanner.Sources;

/// <summary>
/// Catalogue CISA "Known Exploited Vulnerabilities" : failles exploitées activement.
/// Téléchargé en entier à chaque scan (~1 Mo). Sert à :
///   1. relever la criticité (RiskScorer) ;
///   2. détecter qu'une faille déjà connue vient d'entrer au catalogue (alerte d'escalade) ;
///   3. découvrir des CVE exploitées touchant la stack mais pas encore en base.
/// </summary>
public sealed class CisaKevSource(HttpClient http, IOptionsMonitor<SourcesOptions> options)
{
    public bool Enabled => options.CurrentValue.Kev.Enabled;

    public async Task<Dictionary<string, KevEntry>> FetchCatalogAsync(CancellationToken ct)
    {
        using var resp = await http.GetAsync(options.CurrentValue.Kev.BaseUrl, ct);
        resp.EnsureSuccessStatusCode();
        await using var stream = await resp.Content.ReadAsStreamAsync(ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);

        var result = new Dictionary<string, KevEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in doc.RootElement.Arr("vulnerabilities"))
        {
            var id = e.Str("cveID");
            if (id is null) continue;
            result[id] = new KevEntry
            {
                CveId = id,
                VendorProject = e.Str("vendorProject") ?? "",
                Product = e.Str("product") ?? "",
                VulnerabilityName = e.Str("vulnerabilityName") ?? "",
                DateAdded = e.Date("dateAdded"),
                DueDate = e.Date("dueDate"),
                RequiredAction = e.Str("requiredAction"),
                KnownRansomwareCampaignUse = e.Str("knownRansomwareCampaignUse"),
                ShortDescription = e.Str("shortDescription"),
            };
        }
        return result;
    }

    /// <summary>
    /// Rapprochement grossier KEV (texte libre "Microsoft" / "Windows") &lt;-&gt; technologie.
    /// Ne sert qu'à choisir les CVE à télécharger ; la corrélation fine (CPE + version) décide ensuite.
    /// </summary>
    public static bool MightConcern(KevEntry k, ScanTechnology t)
    {
        static string N(string? s) => (s ?? "").ToLowerInvariant().Replace('_', ' ').Replace('-', ' ').Trim();
        var kv = N(k.VendorProject);
        var kp = N(k.Product);
        var tv = N(t.Vendor);
        var tp = N(t.Product);
        var tn = N(t.Name.Replace("(image Docker)", ""));
        if (kp.Length == 0) return false;

        var vendorOk = tv.Length == 0 || kv == tv || kv.Contains(tv) || tv.Contains(kv);
        if (!vendorOk) return false;
        return kp == tp || kp == tn || (kp.Length >= 4 && tn.Contains(kp)) || (tn.Length >= 4 && kp.Contains(tn)) || (tp.Length >= 4 && kp.Contains(tp));
    }
}
