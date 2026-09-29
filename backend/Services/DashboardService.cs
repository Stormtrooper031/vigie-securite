using Dapper;
using Microsoft.Extensions.Options;
using Vigie.Api.Data;
using Vigie.Api.Models;
using Vigie.Shared;

namespace Vigie.Api.Services;

/// <summary>Indicateurs du tableau de bord.</summary>
public sealed class DashboardService(Db db, IOptionsMonitor<NotificationOptions> notif, IOptionsMonitor<SmtpOptions> smtp)
{
    private sealed class SevCount
    {
        public string Severity { get; set; } = "";
        public int Count { get; set; }
    }

    public async Task<DashboardStats> GetAsync(int days = 30)
    {
        await using var cn = await db.OpenAsync();
        var s = new DashboardStats
        {
            TechnologiesActive = await cn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM technologies WHERE is_active"),
            VulnerabilitiesTotal = await cn.ExecuteScalarAsync<int>("SELECT COUNT(DISTINCT vulnerability_id) FROM vulnerability_technology"),
            AlertsOpen = await cn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM alerts WHERE status IN ('new','acknowledged')"),
            KevOpen = await cn.ExecuteScalarAsync<int>("""
                SELECT COUNT(DISTINCT a.vulnerability_id) FROM alerts a JOIN vulnerabilities v ON v.id=a.vulnerability_id
                WHERE v.in_kev AND a.status IN ('new','acknowledged')
                """),
            NewLast7Days = await cn.ExecuteScalarAsync<int>("""
                SELECT COUNT(DISTINCT vulnerability_id) FROM vulnerability_technology vt
                WHERE vt.first_seen_at >= now() - interval '7 days'
                  AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.vulnerability_id=vt.vulnerability_id AND a.technology_id=vt.technology_id AND a.is_baseline)
                """),
        };

        var bySev = await cn.QueryAsync<SevCount>(
            "SELECT severity, COUNT(*) AS count FROM alerts WHERE status IN ('new','acknowledged') GROUP BY severity");
        foreach (var sev in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
            s.OpenBySeverity[sev] = bySev.FirstOrDefault(x => x.Severity == sev)?.Count ?? 0;

        s.TopTechnologies = (await cn.QueryAsync<TechnologyExposure>("""
            SELECT t.id AS technology_id, t.name, t.version,
                   COUNT(*) FILTER (WHERE a.severity='CRITICAL') AS critical, COUNT(*) FILTER (WHERE a.severity='HIGH') AS high,
                   COUNT(*) FILTER (WHERE a.severity='MEDIUM') AS medium, COUNT(*) FILTER (WHERE a.severity='LOW') AS low, COUNT(*) AS total
            FROM alerts a JOIN technologies t ON t.id=a.technology_id
            WHERE a.status IN ('new','acknowledged')
            GROUP BY t.id, t.name, t.version
            ORDER BY critical DESC, high DESC, total DESC
            LIMIT 10
            """)).ToList();

        // Nouvelles alertes par jour (hors inventaire initial)
        var timeline = (await cn.QueryAsync<DailyCount>("""
            SELECT (a.created_at AT TIME ZONE 'UTC')::date AS day,
                   COUNT(*) FILTER (WHERE a.severity='CRITICAL') AS critical, COUNT(*) FILTER (WHERE a.severity='HIGH') AS high,
                   COUNT(*) FILTER (WHERE a.severity='MEDIUM') AS medium, COUNT(*) FILTER (WHERE a.severity='LOW') AS low
            FROM alerts a
            WHERE a.created_at >= now() - make_interval(days => @days) AND NOT a.is_baseline
            GROUP BY 1 ORDER BY 1
            """, new { days })).ToDictionary(d => d.Day.Date);
        for (var d = DateTime.UtcNow.Date.AddDays(-days + 1); d <= DateTime.UtcNow.Date; d = d.AddDays(1))
            { var c = timeline.TryGetValue(d, out var found) ? found : new DailyCount(); c.Day = d; s.Timeline.Add(c); }

        s.LastScan = await cn.QueryFirstOrDefaultAsync<ScanRun>("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1");
        s.LastNotification = await cn.QueryFirstOrDefaultAsync<Notification>(
            "SELECT id, kind, recipients, subject, alert_count, status, error, created_at, sent_at FROM notifications ORDER BY id DESC LIMIT 1");

        var o = notif.CurrentValue;
        s.Settings = new NotificationSettingsView
        {
            Enabled = o.Enabled, To = o.To, MinSeverity = o.MinSeverity, ImmediateSeverity = o.ImmediateSeverity,
            Frequency = o.Frequency, DailyAt = o.DailyAt, SmtpHost = $"{smtp.CurrentValue.Host}:{smtp.CurrentValue.Port}",
            NextDigestAt = NotificationScheduler.NextRun(o, DateTime.Now)?.ToUniversalTime()
        };
        return s;
    }
}
