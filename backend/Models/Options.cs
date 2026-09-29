namespace Vigie.Api.Models;

public class SmtpOptions
{
    public string Host { get; set; } = "mailpit";
    public int Port { get; set; } = 1025;
    public bool EnableSsl { get; set; }
    public string? User { get; set; }
    public string? Password { get; set; }
    public string From { get; set; } = "vigie-securite@localhost";
}

public class NotificationOptions
{
    public bool Enabled { get; set; } = true;
    /// <summary>Destinataires séparés par des virgules.</summary>
    public string To { get; set; } = "";
    /// <summary>Seuil minimal pour figurer dans un courriel.</summary>
    public string MinSeverity { get; set; } = "HIGH";
    /// <summary>Seuil déclenchant un courriel immédiat (NONE = jamais).</summary>
    public string ImmediateSeverity { get; set; } = "CRITICAL";
    /// <summary>immediate | hourly | daily | weekly</summary>
    public string Frequency { get; set; } = "daily";
    public string DailyAt { get; set; } = "07:30";
    public string WeeklyDay { get; set; } = "Monday";
    public bool IncludeBaseline { get; set; }
    public string DashboardUrl { get; set; } = "http://localhost:3000";

    public string[] Recipients => To.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

public class SecurityOptions
{
    /// <summary>Clé partagée exigée sur les routes internes (en-tête X-Api-Key).</summary>
    public string InternalApiKey { get; set; } = "";
}

public class StackOptions
{
    public string File { get; set; } = "/config/stack.txt";
    public bool ImportOnStartup { get; set; } = true;
}

public class ScannerOptions
{
    public string BaseUrl { get; set; } = "http://scanner:8080";
}
