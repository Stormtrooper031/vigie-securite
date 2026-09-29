using Vigie.Shared;

namespace Vigie.Scanner.Models;

/// <summary>Technologie lue en base pour le scan.</summary>
public sealed class ScanTechnology : ITechnologyTarget
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public string Vendor { get; set; } = "";
    public string Product { get; set; } = "";
    public string Version { get; set; } = "";
    public string Ecosystem { get; set; } = "";
    public string? PackageName { get; set; }
    public string? Cpe { get; set; }
    public string? Keywords { get; set; }
    public DateTime? LastScannedAt { get; set; }

    public string Label => string.IsNullOrEmpty(Version) ? Name : $"{Name} {Version}";
}

public sealed record ReferenceLink(string Url, List<string> Tags);

/// <summary>
/// Format pivot : toutes les sources (NVD, OSV, MITRE) sont converties dans cette forme
/// avant d'être fusionnées et enregistrées.
/// </summary>
public sealed class NormalizedVulnerability
{
    public string ExternalId { get; set; } = "";
    public string? CveId { get; set; }
    public HashSet<string> Aliases { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public string? Title { get; set; }
    public string? Description { get; set; }
    public decimal? CvssScore { get; set; }
    public string? CvssVector { get; set; }
    public string? CvssVersion { get; set; }
    public string Severity { get; set; } = Vigie.Shared.Severity.Unknown;
    public string? Cwe { get; set; }
    public string Source { get; set; } = "";
    public string? SourceStatus { get; set; }
    public List<AffectedRule> Affected { get; set; } = [];
    public List<ReferenceLink> References { get; set; } = [];
    public DateTime? PublishedAt { get; set; }
    public DateTime? LastModifiedAt { get; set; }

    // CISA KEV
    public bool InKev { get; set; }
    public DateTime? KevDateAdded { get; set; }
    public DateTime? KevDueDate { get; set; }
    public string? KevRansomware { get; set; }
    public string? KevRequiredAction { get; set; }

    /// <summary>OSV interrogé avec la version exacte : l'appartenance est déjà confirmée par la source.</summary>
    public bool DirectPackageMatch { get; set; }

    public string? FixedVersionsText()
    {
        var fixes = Affected.Select(r => r.EndExcluding).Where(f => !string.IsNullOrWhiteSpace(f)).Distinct()
            .OrderBy(f => f, Comparer<string?>.Create(VersionComparer.Compare)).Take(8).ToList();
        if (fixes.Count == 0) return null;
        var s = string.Join(", ", fixes);
        return s.Length > 500 ? s[..500] : s;
    }
}

public sealed class KevEntry
{
    public string CveId { get; set; } = "";
    public string VendorProject { get; set; } = "";
    public string Product { get; set; } = "";
    public string VulnerabilityName { get; set; } = "";
    public DateTime? DateAdded { get; set; }
    public DateTime? DueDate { get; set; }
    public string? RequiredAction { get; set; }
    public string? KnownRansomwareCampaignUse { get; set; }
    public string? ShortDescription { get; set; }

    public void ApplyTo(NormalizedVulnerability v)
    {
        v.InKev = true;
        v.KevDateAdded = DateAdded;
        v.KevDueDate = DueDate;
        v.KevRequiredAction = RequiredAction;
        v.KevRansomware = KnownRansomwareCampaignUse;
        if (string.IsNullOrWhiteSpace(v.Title)) v.Title = VulnerabilityName;
    }
}

public sealed class AlertIngestItem
{
    public int VulnerabilityId { get; set; }
    public int TechnologyId { get; set; }
    public string Kind { get; set; } = "new";
    public bool IsBaseline { get; set; }
    public string Confidence { get; set; } = MatchConfidence.Confirmed;
}

/// <summary>Journal d'un scan (stocké dans scan_runs.log et affiché dans le tableau de bord).</summary>
public sealed class ScanLog(ILogger logger)
{
    private readonly List<string> _lines = [];
    private readonly Lock _lock = new();
    public int Errors { get; private set; }

    public void Info(string message)
    {
        logger.LogInformation("{Message}", message);
        lock (_lock) _lines.Add($"{DateTime.Now:HH:mm:ss} {message}");
    }

    public void Error(string message, Exception? ex = null)
    {
        logger.LogError(ex, "{Message}", message);
        lock (_lock) { _lines.Add($"{DateTime.Now:HH:mm:ss} ERREUR {message}{(ex is null ? "" : " : " + ex.Message)}"); Errors++; }
    }

    public override string ToString()
    {
        lock (_lock)
        {
            var s = string.Join('\n', _lines);
            return s.Length > 60_000 ? s[..60_000] + "\n[...]" : s;
        }
    }
}
