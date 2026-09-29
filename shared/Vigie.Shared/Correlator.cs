namespace Vigie.Shared;

/// <summary>Ce que le corrélateur a besoin de connaître d'une technologie.</summary>
public interface ITechnologyTarget
{
    string Type { get; }
    string Vendor { get; }
    string Product { get; }
    string Version { get; }
    string Ecosystem { get; }
    string? PackageName { get; }
}

public static class MatchConfidence
{
    public const string Confirmed = "confirmed"; // version installée dans la plage vulnérable
    public const string Probable = "probable";   // version partielle/inconnue ou donnée source imprécise
}

public sealed record CorrelationMatch(string Confidence, string Rule, string Source, string? FixedIn);

/// <summary>
/// Corrélation faille &lt;-&gt; technologie : le produit correspond-il, et la version
/// installée est-elle dans une plage vulnérable ?
/// </summary>
public static class Correlator
{
    public static CorrelationMatch? Match(ITechnologyTarget tech, IEnumerable<AffectedRule> rules)
    {
        CorrelationMatch? best = null;
        foreach (var rule in rules)
        {
            if (!ProductMatches(tech, rule)) continue;
            var (ok, partial) = VersionMatches(tech.Version, rule);
            if (!ok) continue;
            var m = new CorrelationMatch(partial ? MatchConfidence.Probable : MatchConfidence.Confirmed, rule.Describe(), rule.Source, rule.EndExcluding);
            if (m.Confidence == MatchConfidence.Confirmed) return m;
            best ??= m;
        }
        return best;
    }

    public static bool ProductMatches(ITechnologyTarget tech, AffectedRule rule)
    {
        if (rule.Kind == "pkg")
        {
            if (string.IsNullOrEmpty(tech.Ecosystem) || string.IsNullOrEmpty(tech.PackageName)) return false;
            var eco = rule.Ecosystem ?? "";
            var ecoOk = eco.Equals(tech.Ecosystem, StringComparison.OrdinalIgnoreCase)
                        || eco.StartsWith(tech.Ecosystem + ":", StringComparison.OrdinalIgnoreCase);
            return ecoOk && string.Equals(rule.Package, tech.PackageName, StringComparison.OrdinalIgnoreCase);
        }

        if (string.IsNullOrEmpty(tech.Product) || string.IsNullOrEmpty(rule.Product)) return false;
        // Paquet d'écosystème sans vendeur CPE connu : seules les règles "pkg" (OSV) s'appliquent
        if (!string.IsNullOrEmpty(tech.Ecosystem) && string.IsNullOrEmpty(tech.Vendor)) return false;

        if (rule.Source == "MITRE")
        {
            // Données CNA en texte libre ("Microsoft", "ASP.NET Core 8.0") : comparaison par mots
            var vendorOk = string.IsNullOrEmpty(tech.Vendor) || ContainsWords(rule.Vendor, tech.Vendor) || ContainsWords(rule.Product, tech.Vendor);
            return vendorOk && ContainsWords(rule.Product, tech.Product);
        }

        var productOk = Norm(rule.Product) == Norm(tech.Product);
        var vendorMatch = string.IsNullOrEmpty(tech.Vendor) || string.IsNullOrEmpty(rule.Vendor) || Norm(rule.Vendor) == Norm(tech.Vendor);
        return productOk && vendorMatch;
    }

    /// <summary>(correspond ?, partiel ?) — partiel = corrélation "probable".</summary>
    public static (bool Match, bool Partial) VersionMatches(string? techVersion, AffectedRule rule)
    {
        if (VersionComparer.IsWildcard(techVersion)) return (true, true); // version inconnue : toutes les failles du produit

        var v = techVersion!;
        if (rule.Versions is { Count: > 0 })
        {
            if (rule.Versions.Any(x => VersionComparer.AreEqual(x, v))) return (true, false);
            if (rule.Versions.Any(x => VersionComparer.IsPrefixOf(v, x))) return (true, true);
            if (!rule.HasRange) return (false, false);
        }

        if (!VersionComparer.IsWildcard(rule.Version))
        {
            if (VersionComparer.AreEqual(rule.Version, v)) return (true, false);
            if (VersionComparer.IsPrefixOf(v, rule.Version)) return (true, true);
            return (false, false);
        }

        if (!rule.HasRange) return (true, true); // "toutes versions" : donnée source peu précise

        var depth = VersionComparer.NumericDepth(v);
        var boundDepth = new[] { rule.StartIncluding, rule.StartExcluding, rule.EndIncluding, rule.EndExcluding }
            .Where(b => b is not null).Select(VersionComparer.NumericDepth).DefaultIfEmpty(0).Max();
        var partial = depth > 0 && depth < boundDepth;

        // Version partielle "11.4" = intervalle [11.4, 11.5[ : on teste le chevauchement
        var lo = v;
        var hi = partial ? NextMinor(v) : v;

        if (rule.StartIncluding is not null && VersionComparer.Compare(partial ? hi : lo, rule.StartIncluding) < (partial ? 1 : 0)) return (false, false);
        if (rule.StartExcluding is not null && VersionComparer.Compare(hi, rule.StartExcluding) <= 0) return (false, false);
        if (rule.EndIncluding is not null && VersionComparer.Compare(lo, rule.EndIncluding) > 0) return (false, false);
        if (rule.EndExcluding is not null && VersionComparer.Compare(lo, rule.EndExcluding) >= 0) return (false, false);
        return (true, partial);
    }

    /// <summary>"11.4" -> "11.5" ; "8" -> "9".</summary>
    private static string NextMinor(string version)
    {
        var parts = VersionComparer.Clean(version).Split('.', '-', '_').TakeWhile(p => p.Length > 0 && p.All(char.IsDigit)).ToList();
        if (parts.Count == 0) return version;
        parts[^1] = (long.Parse(parts[^1]) + 1).ToString();
        return string.Join('.', parts);
    }

    public static string Norm(string? s) => (s ?? "").Trim().ToLowerInvariant().Replace(' ', '_').Replace("\\", "");

    private static bool ContainsWords(string? haystack, string? needle)
    {
        if (string.IsNullOrWhiteSpace(haystack) || string.IsNullOrWhiteSpace(needle)) return false;
        var h = Words(haystack);
        var n = Words(needle);
        if (n.Length == 0) return false;
        for (var i = 0; i + n.Length <= h.Length; i++)
            if (n.Select((w, j) => h[i + j] == w).All(x => x)) return true;
        return false;
    }

    private static string[] Words(string s) =>
        s.ToLowerInvariant().Split([' ', '_', '/', ',', '(', ')'], StringSplitOptions.RemoveEmptyEntries);
}
