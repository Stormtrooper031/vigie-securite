namespace Vigie.Api.Models;

/// <summary>Alerte = une faille pertinente pour une technologie de ma stack (table alerts).</summary>
public class Alert
{
    public int Id { get; set; }
    public int VulnerabilityId { get; set; }
    public int TechnologyId { get; set; }
    public string Kind { get; set; } = "new";
    public string Severity { get; set; } = "";
    public int RiskScore { get; set; }
    public string Status { get; set; } = AlertStatus.New;
    public bool IsBaseline { get; set; }
    public string? Reason { get; set; }
    public int? NotificationId { get; set; }
    public DateTime? NotifiedAt { get; set; }
    public DateTime? StatusChangedAt { get; set; }
    public string? StatusComment { get; set; }
    public DateTime CreatedAt { get; set; }

    // Jointures
    public string? ExternalId { get; set; }
    public string? CveId { get; set; }
    public string? Title { get; set; }
    public decimal? CvssScore { get; set; }
    public decimal? EpssScore { get; set; }
    public bool InKev { get; set; }
    public DateTime? KevDueDate { get; set; }
    public string? FixedVersions { get; set; }
    public DateTime? PublishedAt { get; set; }
    public string? TechnologyName { get; set; }
    public string? TechnologyVersion { get; set; }
    public string? Confidence { get; set; }
}

public static class AlertStatus
{
    public const string New = "new";
    public const string Acknowledged = "acknowledged";
    public const string Resolved = "resolved";
    public const string Ignored = "ignored";
    public static readonly string[] All = [New, Acknowledged, Resolved, Ignored];
}

public class AlertStatusUpdate
{
    public string Status { get; set; } = "";
    public string? Comment { get; set; }
}

public class AlertBulkStatusUpdate : AlertStatusUpdate
{
    public List<int> Ids { get; set; } = [];
}

/// <summary>Appel interne du scanner : nouvelles corrélations à transformer en alertes.</summary>
public class AlertIngestRequest
{
    public int? ScanRunId { get; set; }
    public List<AlertIngestItem> Items { get; set; } = [];
}

public class AlertIngestItem
{
    public int VulnerabilityId { get; set; }
    public int TechnologyId { get; set; }
    public string Kind { get; set; } = "new";          // new | kev
    public bool IsBaseline { get; set; }
    public string Confidence { get; set; } = "confirmed";
}

public class AlertIngestResult
{
    public int Created { get; set; }
    public int Skipped { get; set; }
    public int ImmediateNotificationId { get; set; }
}

public class AlertQuery
{
    public string? Status { get; set; }
    public string? Severity { get; set; }
    public int? TechnologyId { get; set; }
    public bool IncludeBaseline { get; set; } = true;
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 50;
}
