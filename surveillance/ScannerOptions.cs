namespace Vigie.Scanner;

public class ScanOptions
{
    /// <summary>Intervalle entre deux scans (minutes).</summary>
    public int IntervalMinutes { get; set; } = 360;
    /// <summary>Heure fixe quotidienne "HH:mm" (prioritaire sur l'intervalle si renseignée).</summary>
    public string? DailyAt { get; set; }
    public bool OnStartup { get; set; } = true;
    public int StartupDelaySeconds { get; set; } = 30;
    /// <summary>Nombre max de CVE enrichies via MITRE par scan (API publique : rester raisonnable).</summary>
    public int MitreBudgetPerRun { get; set; } = 300;
    /// <summary>Nombre max de CVE du catalogue KEV absentes de la base récupérées par scan.</summary>
    public int KevFetchBudgetPerRun { get; set; } = 150;
}

public class SourcesOptions
{
    public NvdOptions Nvd { get; set; } = new();
    public SimpleSource Kev { get; set; } = new() { BaseUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" };
    public SimpleSource Mitre { get; set; } = new() { BaseUrl = "https://cveawg.mitre.org/api/cve/" };
    public SimpleSource Osv { get; set; } = new() { BaseUrl = "https://api.osv.dev/v1/query" };
    public SimpleSource Epss { get; set; } = new() { BaseUrl = "https://api.first.org/data/v1/epss" };
}

public class SimpleSource
{
    public bool Enabled { get; set; } = true;
    public string BaseUrl { get; set; } = "";
}

public class NvdOptions : SimpleSource
{
    public NvdOptions() => BaseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    /// <summary>Clé API gratuite : 50 requêtes / 30 s au lieu de 5.</summary>
    public string? ApiKey { get; set; }
    /// <summary>Premier scan : 0 = tout l'historique, N = CVE modifiées dans les N derniers jours.</summary>
    public int InitialLookbackDays { get; set; }
}

public class BackendOptions
{
    public string BaseUrl { get; set; } = "http://backend:8080";
}

public class SecurityOptions
{
    public string InternalApiKey { get; set; } = "";
}
