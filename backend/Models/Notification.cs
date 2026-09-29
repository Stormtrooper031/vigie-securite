namespace Vigie.Api.Models;

/// <summary>Courriel envoyé (table notifications).</summary>
public class Notification
{
    public int Id { get; set; }
    public string Kind { get; set; } = "";
    public string Recipients { get; set; } = "";
    public string Subject { get; set; } = "";
    public string? BodyHtml { get; set; }
    public int AlertCount { get; set; }
    public string Status { get; set; } = "pending";
    public string? Error { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? SentAt { get; set; }
}

public class ScanRun
{
    public int Id { get; set; }
    public string TriggerSource { get; set; } = "";
    public string Status { get; set; } = "";
    public int TechnologiesScanned { get; set; }
    public int VulnsFetched { get; set; }
    public int VulnsNew { get; set; }
    public int LinksNew { get; set; }
    public int KevUpdates { get; set; }
    public string? Log { get; set; }
    public DateTime StartedAt { get; set; }
    public DateTime? FinishedAt { get; set; }
}

public class DashboardStats
{
    public int TechnologiesActive { get; set; }
    public int VulnerabilitiesTotal { get; set; }
    public int AlertsOpen { get; set; }
    public int KevOpen { get; set; }
    public int NewLast7Days { get; set; }
    public Dictionary<string, int> OpenBySeverity { get; set; } = [];
    public List<TechnologyExposure> TopTechnologies { get; set; } = [];
    public List<DailyCount> Timeline { get; set; } = [];
    public ScanRun? LastScan { get; set; }
    public Notification? LastNotification { get; set; }
    public NotificationSettingsView Settings { get; set; } = new();
}

public class TechnologyExposure
{
    public int TechnologyId { get; set; }
    public string Name { get; set; } = "";
    public string Version { get; set; } = "";
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int Total { get; set; }
}

public class DailyCount
{
    public DateTime Day { get; set; }
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
}

public class NotificationSettingsView
{
    public bool Enabled { get; set; }
    public string To { get; set; } = "";
    public string MinSeverity { get; set; } = "";
    public string ImmediateSeverity { get; set; } = "";
    public string Frequency { get; set; } = "";
    public string DailyAt { get; set; } = "";
    public string SmtpHost { get; set; } = "";
    public DateTime? NextDigestAt { get; set; }
}
