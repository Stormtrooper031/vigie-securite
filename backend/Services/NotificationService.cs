using Dapper;
using Microsoft.Extensions.Options;
using Vigie.Api.Data;
using Vigie.Api.Models;
using Vigie.Shared;

namespace Vigie.Api.Services;

/// <summary>
/// Construction et envoi des courriels. Idempotent : seules les alertes non encore
/// notifiées (notified_at IS NULL) sont envoyées, donc un redémarrage ne crée pas de doublon.
/// Si l'envoi échoue, les alertes restent en attente et repartiront au prochain cycle.
/// </summary>
public sealed class NotificationService(Db db, EmailSender sender, IOptionsMonitor<NotificationOptions> options, ILogger<NotificationService> logger)
{
    private static readonly SemaphoreSlim Gate = new(1, 1);

    public async Task<Notification?> SendPendingAsync(string kind, string minSeverity, bool includeBaselineSummary, CancellationToken ct = default)
    {
        var o = options.CurrentValue;
        if (!o.Enabled) return null;

        await Gate.WaitAsync(ct);
        try
        {
            var sevs = Severity.Ordered.Where(s => s != Severity.None && Severity.AtLeast(s, minSeverity)).ToArray();

            await using var cn = await db.OpenAsync(ct);
            var alerts = (await cn.QueryAsync<Alert>(AlertService.AlertSelect + """
                 WHERE a.notified_at IS NULL AND a.status = 'new' AND a.severity = ANY(@sevs)
                   AND (NOT a.is_baseline OR (@inclBaseline AND NOT @detailBaseline))
                 ORDER BY a.risk_score DESC, a.created_at DESC
                 LIMIT 200
                """, new { sevs, inclBaseline = o.IncludeBaseline, detailBaseline = includeBaselineSummary })).ToList();

            // Inventaire initial : toutes les failles, détaillées une à une (aucune limite, toutes criticités)
            var baselineAlerts = includeBaselineSummary
                ? (await cn.QueryAsync<Alert>(AlertService.AlertSelect + """
                     WHERE a.notified_at IS NULL AND a.is_baseline
                     ORDER BY t.name, t.version, a.risk_score DESC, a.created_at DESC
                    """)).ToList()
                : [];

            var baseline = includeBaselineSummary
                ? (await cn.QueryAsync<BaselineSummaryRow>("""
                    SELECT t.name AS technology_name, t.version AS technology_version, COUNT(*) AS total,
                           COUNT(*) FILTER (WHERE a.severity='CRITICAL') AS critical, COUNT(*) FILTER (WHERE a.severity='HIGH') AS high
                    FROM alerts a JOIN technologies t ON t.id = a.technology_id
                    WHERE a.notified_at IS NULL AND a.is_baseline
                    GROUP BY t.id, t.name, t.version ORDER BY critical DESC, total DESC
                    """)).ToList()
                : [];

            if (alerts.Count == 0 && baseline.Count == 0) return null;

            var subject = EmailTemplateBuilder.Subject(kind, alerts, baseline.Sum(b => b.Total));
            var html = EmailTemplateBuilder.Html(kind, alerts, baseline, o.DashboardUrl.TrimEnd('/'), baselineAlerts);
            var text = EmailTemplateBuilder.Text(kind, alerts, baseline, o.DashboardUrl.TrimEnd('/'), baselineAlerts);
            var recipients = string.Join(",", o.Recipients);

            var id = await cn.ExecuteScalarAsync<int>("""
                INSERT INTO notifications (kind, recipients, subject, body_html, alert_count, status)
                VALUES (@kind, @recipients, @subject, @html, @count, 'pending')
                RETURNING id;
                """, new { kind, recipients, subject, html, count = alerts.Count });

            try
            {
                await sender.SendAsync(o.Recipients, subject, html, text, ct);
                await cn.ExecuteAsync("UPDATE notifications SET status='sent', sent_at=now() WHERE id=@id", new { id });

                if (alerts.Count > 0)
                    await cn.ExecuteAsync("UPDATE alerts SET notified_at=now(), notification_id=@id WHERE id = ANY(@ids)",
                        new { id, ids = alerts.Select(a => a.Id).ToArray() });
                if (baseline.Count > 0)
                    await cn.ExecuteAsync("UPDATE alerts SET notified_at=now(), notification_id=@id WHERE notified_at IS NULL AND is_baseline", new { id });
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Échec d'envoi SMTP (notification {Id})", id);
                await cn.ExecuteAsync("UPDATE notifications SET status='failed', error=@err WHERE id=@id", new { id, err = FullMessage(ex) });
            }

            return await cn.QuerySingleAsync<Notification>("SELECT * FROM notifications WHERE id=@id", new { id });
        }
        finally
        {
            Gate.Release();
        }
    }

    public async Task<Notification> SendTestAsync(string? to, CancellationToken ct = default)
    {
        var o = options.CurrentValue;
        var recipients = string.IsNullOrWhiteSpace(to) ? o.Recipients : to.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var sample = new List<Alert>
        {
            new() { Id = 0, ExternalId = "CVE-2021-44228", CveId = "CVE-2021-44228", Severity = Severity.Critical, RiskScore = 99,
                    Title = "Exemple : Apache Log4j2 JNDI (Log4Shell)", CvssScore = 10.0m, EpssScore = 0.97m, InKev = true,
                    TechnologyName = "Apache Log4j", TechnologyVersion = "2.14.1", FixedVersions = "2.17.1" }
        };
        var subject = "Vigie sécurité : courriel de test";
        var html = EmailTemplateBuilder.Html("test", sample, [], o.DashboardUrl.TrimEnd('/'));
        var text = EmailTemplateBuilder.Text("test", sample, [], o.DashboardUrl.TrimEnd('/'));

        await using var cn = await db.OpenAsync(ct);
        var id = await cn.ExecuteScalarAsync<int>("""
            INSERT INTO notifications (kind, recipients, subject, body_html, alert_count, status)
            VALUES ('test', @r, @subject, @html, 0, 'pending') RETURNING id;
            """, new { r = string.Join(",", recipients), subject, html });
        try
        {
            await sender.SendAsync(recipients, subject, html, text, ct);
            await cn.ExecuteAsync("UPDATE notifications SET status='sent', sent_at=now() WHERE id=@id", new { id });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Échec d'envoi SMTP (courriel de test {Id})", id);
            await cn.ExecuteAsync("UPDATE notifications SET status='failed', error=@err WHERE id=@id", new { id, err = FullMessage(ex) });
        }
        return await cn.QuerySingleAsync<Notification>("SELECT * FROM notifications WHERE id=@id", new { id });
    }

    /// <summary>« Failure sending mail. » seul est inutile : on remonte les causes internes (TLS, authentification...).</summary>
    private static string FullMessage(Exception ex)
    {
        var parts = new List<string>();
        for (var e = ex; e is not null; e = e.InnerException) parts.Add(e.Message);
        return string.Join(" → ", parts);
    }

    public async Task<List<Notification>> ListAsync(int limit = 100)
    {
        await using var cn = await db.OpenAsync();
        return (await cn.QueryAsync<Notification>(
            "SELECT id, kind, recipients, subject, alert_count, status, error, created_at, sent_at FROM notifications ORDER BY id DESC LIMIT @limit",
            new { limit })).ToList();
    }

    public async Task<Notification?> GetAsync(int id)
    {
        await using var cn = await db.OpenAsync();
        return await cn.QuerySingleOrDefaultAsync<Notification>("SELECT * FROM notifications WHERE id=@id", new { id });
    }
}
