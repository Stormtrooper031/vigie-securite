using Dapper;
using Microsoft.Extensions.Options;
using Vigie.Api.Data;
using Vigie.Api.Models;
using Vigie.Shared;

namespace Vigie.Api.Services;

/// <summary>Création (avec calcul de criticité), consultation et suivi des alertes.</summary>
public sealed class AlertService(Db db, NotificationService notifications, IOptionsMonitor<NotificationOptions> notifOptions, ILogger<AlertService> logger)
{
    private sealed class VulnFacts
    {
        public int Id { get; set; }
        public decimal? CvssScore { get; set; }
        public string? Severity { get; set; }
        public bool InKev { get; set; }
        public decimal? EpssScore { get; set; }
        public DateTime? KevDueDate { get; set; }
        public string? FixedVersions { get; set; }
    }

    public const string AlertSelect = """
        SELECT a.*, v.external_id, v.cve_id, v.title, v.cvss_score, v.epss_score, v.in_kev, v.kev_due_date,
               COALESCE(vt.fixed_version, v.fixed_versions) AS fixed_versions, v.published_at, t.name AS technology_name, t.version AS technology_version,
               vt.confidence
        FROM alerts a
        JOIN vulnerabilities v ON v.id = a.vulnerability_id
        JOIN technologies t ON t.id = a.technology_id
        LEFT JOIN vulnerability_technology vt ON vt.vulnerability_id = a.vulnerability_id AND vt.technology_id = a.technology_id
        """;

    /// <summary>Transforme des corrélations en alertes, puis déclenche l'envoi immédiat si le seuil est atteint.</summary>
    public async Task<AlertIngestResult> IngestAsync(AlertIngestRequest request)
    {
        var result = new AlertIngestResult();
        if (request.Items.Count == 0) return result;

        var ids = request.Items.Select(i => i.VulnerabilityId).Distinct().ToArray();
        var createdSeverities = new List<string>();

        await using (var cn = await db.OpenAsync())
        {
            var facts = (await cn.QueryAsync<VulnFacts>(
                "SELECT id, cvss_score, severity, in_kev, epss_score, kev_due_date, fixed_versions FROM vulnerabilities WHERE id = ANY(@ids)",
                new { ids })).ToDictionary(f => f.Id);
            var fixes = (await cn.QueryAsync<(int Vid, int Tid, string? Fixed)>(
                "SELECT vulnerability_id, technology_id, fixed_version FROM vulnerability_technology WHERE vulnerability_id = ANY(@ids)",
                new { ids })).ToDictionary(x => (x.Vid, x.Tid), x => x.Fixed);

            foreach (var item in request.Items)
            {
                if (!facts.TryGetValue(item.VulnerabilityId, out var f)) { result.Skipped++; continue; }
                var risk = RiskScorer.Compute(f.CvssScore, f.Severity, f.InKev, f.EpssScore, item.Confidence);
                var kind = item.Kind is "kev" or "rescored" ? item.Kind : "new";
                var reason = kind == "kev"
                    ? $"Ajoutée au catalogue CISA KEV (exploitation active){(f.KevDueDate is { } d ? $", échéance CISA {d:yyyy-MM-dd}" : "")} ; {risk.Explanation}"
                    : risk.Explanation;
                var fixedIn = fixes.GetValueOrDefault((item.VulnerabilityId, item.TechnologyId)) ?? f.FixedVersions;
                if (!string.IsNullOrEmpty(fixedIn)) reason += $" ; corrigée en {fixedIn}";

                var rows = await cn.ExecuteAsync("""
                    INSERT INTO alerts (vulnerability_id, technology_id, kind, severity, risk_score, is_baseline, reason)
                    VALUES (@vid, @tid, @kind, @sev, @score, @baseline, @reason)
                    ON CONFLICT (vulnerability_id, technology_id, kind) DO NOTHING
                    """, new { vid = item.VulnerabilityId, tid = item.TechnologyId, kind, sev = risk.Severity, score = risk.RiskScore,
                               baseline = item.IsBaseline, reason = reason.Length > 500 ? reason[..500] : reason });
                if (kind == "kev")
                {
                    // Escalade : la criticité de l'alerte d'origine est recalculée (KEV)
                    await cn.ExecuteAsync("""
                        UPDATE alerts SET severity=@sev, risk_score=@score
                        WHERE vulnerability_id=@vid AND technology_id=@tid AND kind='new'
                        """, new { vid = item.VulnerabilityId, tid = item.TechnologyId, sev = risk.Severity, score = risk.RiskScore });
                }
                if (rows > 0)
                {
                    result.Created++;
                    if (!item.IsBaseline) createdSeverities.Add(risk.Severity);
                }
                else result.Skipped++;
            }
        }

        // Envoi immédiat
        var o = notifOptions.CurrentValue;
        if (result.Created > 0 && o.Enabled)
        {
            string? threshold = null;
            if (o.Frequency.Equals("immediate", StringComparison.OrdinalIgnoreCase)) threshold = o.MinSeverity;
            else if (!o.ImmediateSeverity.Equals("NONE", StringComparison.OrdinalIgnoreCase)
                     && createdSeverities.Any(s => Severity.AtLeast(s, o.ImmediateSeverity)))
                threshold = Severity.Max(o.ImmediateSeverity, o.MinSeverity);

            if (threshold is not null)
            {
                try
                {
                    var n = await notifications.SendPendingAsync("immediate", threshold, includeBaselineSummary: false);
                    result.ImmediateNotificationId = n?.Id ?? 0;
                }
                catch (Exception ex) { logger.LogError(ex, "Échec de l'envoi immédiat"); }
            }
        }

        logger.LogInformation("Alertes : {Created} créées, {Skipped} ignorées (déjà existantes)", result.Created, result.Skipped);
        return result;
    }

    public async Task<PagedResult<Alert>> QueryAsync(AlertQuery q)
    {
        var where = new List<string>();
        var p = new DynamicParameters();
        if (!string.IsNullOrWhiteSpace(q.Status)) { where.Add("a.status = ANY(@statuses)"); p.Add("statuses", q.Status.Split(',', StringSplitOptions.TrimEntries)); }
        if (!string.IsNullOrWhiteSpace(q.Severity)) { where.Add("a.severity = ANY(@sevs)"); p.Add("sevs", q.Severity.ToUpperInvariant().Split(',', StringSplitOptions.TrimEntries)); }
        if (q.TechnologyId is not null) { where.Add("a.technology_id = @tid"); p.Add("tid", q.TechnologyId); }
        if (!q.IncludeBaseline) where.Add("NOT a.is_baseline");

        var whereSql = where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : "";
        var pageSize = Math.Clamp(q.PageSize, 1, 500);
        var page = Math.Max(1, q.Page);
        p.Add("limit", pageSize);
        p.Add("offset", (page - 1) * pageSize);

        await using var cn = await db.OpenAsync();
        var total = await cn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM alerts a" + whereSql, p);
        var items = (await cn.QueryAsync<Alert>(AlertSelect + whereSql + """
             ORDER BY array_position(ARRAY['new','acknowledged','resolved','ignored'], a.status::text), a.risk_score DESC, a.created_at DESC
             LIMIT @limit OFFSET @offset
            """, p)).ToList();
        return new PagedResult<Alert> { Items = items, Total = total, Page = page, PageSize = pageSize };
    }

    public async Task<int> UpdateStatusAsync(IEnumerable<int> ids, string status, string? comment)
    {
        if (!AlertStatus.All.Contains(status)) throw new ArgumentException($"Statut invalide : {status}");
        var idArr = ids.ToArray();
        if (idArr.Length == 0) return 0;
        await using var cn = await db.OpenAsync();
        return await cn.ExecuteAsync("""
            UPDATE alerts SET status=@status, status_comment=@comment, status_changed_at=now() WHERE id = ANY(@ids)
            """, new { status, comment, ids = idArr });
    }
}
