namespace Vigie.Shared;

/// <summary>Niveaux de criticité et conversions (CVSS -> libellé, comparaison).</summary>
public static class Severity
{
    public const string Critical = "CRITICAL";
    public const string High = "HIGH";
    public const string Medium = "MEDIUM";
    public const string Low = "LOW";
    public const string None = "NONE";
    public const string Unknown = "UNKNOWN";

    public static readonly string[] Ordered = [Critical, High, Medium, Low, None, Unknown];

    /// <summary>Rang numérique : plus c'est haut, plus c'est grave.</summary>
    public static int Rank(string? severity) => Normalize(severity) switch
    {
        Critical => 5,
        High => 4,
        Medium => 3,
        Unknown => 2,
        Low => 1,
        _ => 0
    };

    public static string Normalize(string? severity)
    {
        var s = (severity ?? "").Trim().ToUpperInvariant();
        return s switch
        {
            "CRITICAL" or "CRITIQUE" => Critical,
            "HIGH" or "ELEVEE" or "ÉLEVÉE" or "IMPORTANT" => High,
            "MEDIUM" or "MODERATE" or "MOYENNE" => Medium,
            "LOW" or "FAIBLE" => Low,
            "NONE" or "AUCUNE" => None,
            _ => Unknown
        };
    }

    /// <summary>Échelle CVSS v3/v4 officielle.</summary>
    public static string FromCvss(decimal? score)
    {
        if (score is null) return Unknown;
        return score.Value switch
        {
            >= 9.0m => Critical,
            >= 7.0m => High,
            >= 4.0m => Medium,
            > 0m => Low,
            _ => None
        };
    }

    public static bool AtLeast(string? severity, string? threshold) => Rank(severity) >= Rank(threshold);

    public static string Max(string a, string b) => Rank(a) >= Rank(b) ? a : b;

    public static string BumpOne(string severity) => Normalize(severity) switch
    {
        Low => Medium,
        Medium => High,
        Unknown => High,
        High => Critical,
        var s => s
    };

    public static string Label(string? severity) => Normalize(severity) switch
    {
        Critical => "Critique",
        High => "Élevée",
        Medium => "Moyenne",
        Low => "Faible",
        None => "Aucune",
        _ => "Inconnue"
    };
}
