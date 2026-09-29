using System.Text.Json;
using System.Text.Json.Serialization;

namespace Vigie.Shared;

/// <summary>
/// Règle normalisée "ce produit, dans ces versions, est vulnérable".
/// Stockée en JSON dans vulnerabilities.affected pour permettre de refaire
/// la corrélation quand une technologie est ajoutée ou change de version.
///   Kind = "cpe" : issue de NVD (configurations) ou MITRE (affected vendor/product)
///   Kind = "pkg" : issue d'OSV (écosystème + nom de paquet)
/// </summary>
public sealed class AffectedRule
{
    public string Kind { get; set; } = "cpe";
    public string Source { get; set; } = "NVD";

    // cpe
    public string? Part { get; set; }
    public string? Vendor { get; set; }
    public string? Product { get; set; }

    // pkg
    public string? Ecosystem { get; set; }
    public string? Package { get; set; }

    // versions
    public string? Version { get; set; }              // version exacte (sinon * = toutes)
    public string? StartIncluding { get; set; }
    public string? StartExcluding { get; set; }
    public string? EndIncluding { get; set; }
    public string? EndExcluding { get; set; }         // = version corrigée
    public List<string>? Versions { get; set; }       // liste explicite (OSV)

    [JsonIgnore]
    public bool HasRange => StartIncluding is not null || StartExcluding is not null || EndIncluding is not null || EndExcluding is not null;

    public string Describe()
    {
        var who = Kind == "pkg" ? $"{Ecosystem}/{Package}" : $"{Vendor}:{Product}";
        var parts = new List<string>();
        if (!VersionComparer.IsWildcard(Version)) parts.Add($"= {Version}");
        if (StartIncluding is not null) parts.Add($">= {StartIncluding}");
        if (StartExcluding is not null) parts.Add($"> {StartExcluding}");
        if (EndIncluding is not null) parts.Add($"<= {EndIncluding}");
        if (EndExcluding is not null) parts.Add($"< {EndExcluding}");
        if (Versions is { Count: > 0 }) parts.Add($"versions listées ({Versions.Count})");
        if (parts.Count == 0) parts.Add("toutes versions");
        return $"{Source} {who} {string.Join(" ", parts)}";
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string Serialize(IEnumerable<AffectedRule> rules) => JsonSerializer.Serialize(rules, JsonOpts);

    public static List<AffectedRule> Deserialize(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try { return JsonSerializer.Deserialize<List<AffectedRule>>(json, JsonOpts) ?? []; }
        catch (JsonException) { return []; }
    }
}
