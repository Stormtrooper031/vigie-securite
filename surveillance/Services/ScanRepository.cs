using System.Text.Json;
using Dapper;
using Npgsql;
using Vigie.Scanner.Models;
using Vigie.Scanner.Sources;
using Vigie.Shared;

namespace Vigie.Scanner.Services;

/// <summary>Accès PostgreSQL du service de surveillance (Npgsql + Dapper).</summary>
public sealed class ScanRepository(IConfiguration config)
{
    private readonly NpgsqlDataSource _dataSource = NpgsqlDataSource.Create(
        config.GetConnectionString("Vigie") ?? throw new InvalidOperationException("ConnectionStrings:Vigie manquant"));

    private async Task<NpgsqlConnection> OpenAsync(CancellationToken ct = default) => await _dataSource.OpenConnectionAsync(ct);

    public async Task WaitUntilReadyAsync(ILogger logger, CancellationToken ct)
    {
        for (var i = 1; ; i++)
        {
            try { await using var cn = await OpenAsync(ct); return; }
            catch (NpgsqlException ex) when (i < 30)
            {
                logger.LogWarning("PostgreSQL indisponible ({Attempt}/30) : {Message}", i, ex.Message);
                await Task.Delay(3000, ct);
            }
        }
    }

    // ------------------------------------------------------------------ technologies

    public async Task<List<ScanTechnology>> GetTechnologiesAsync(int? id, CancellationToken ct)
    {
        await using var cn = await OpenAsync(ct);
        return (await cn.QueryAsync<ScanTechnology>(
            "SELECT id, name, type, vendor, product, version, ecosystem, package_name, cpe, keywords, last_scanned_at " +
            "FROM technologies WHERE is_active" + (id is null ? "" : " AND id = @id") + " ORDER BY id", new { id })).ToList();
    }

    public async Task MarkScannedAsync(int technologyId, DateTime whenUtc, CancellationToken ct)
    {
        await using var cn = await OpenAsync(ct);
        await cn.ExecuteAsync("UPDATE technologies SET last_scanned_at=@whenUtc WHERE id=@technologyId", new { whenUtc, technologyId });
    }

    // ------------------------------------------------------------------ scan_runs

    public async Task<int> StartRunAsync(string trigger, CancellationToken ct)
    {
        await using var cn = await OpenAsync(ct);
        return await cn.ExecuteScalarAsync<int>(
            "INSERT INTO scan_runs (trigger_source, status, started_at) VALUES (@trigger, 'running', now()) RETURNING id;",
            new { trigger });
    }

    public async Task FinishRunAsync(int id, string status, ScanStats s, string log)
    {
        await using var cn = await OpenAsync();
        await cn.ExecuteAsync("""
            UPDATE scan_runs SET status=@status, technologies_scanned=@TechnologiesScanned, vulns_fetched=@VulnsFetched,
                   vulns_new=@VulnsNew, links_new=@LinksNew, kev_updates=@KevUpdates, log=@log, finished_at=now()
            WHERE id=@id
            """, new { id, status, s.TechnologiesScanned, s.VulnsFetched, s.VulnsNew, s.LinksNew, s.KevUpdates, log });
    }

    /// <summary>Scans restés "running" après un arrêt brutal du conteneur.</summary>
    public async Task CloseOrphanRunsAsync()
    {
        await using var cn = await OpenAsync();
        await cn.ExecuteAsync("UPDATE scan_runs SET status='failed', finished_at=now(), log=COALESCE(log,'') || chr(10) || 'Interrompu (redémarrage du service)' WHERE status='running'");
    }

    // ------------------------------------------------------------------ vulnerabilities

    private sealed class VulnRow
    {
        public int Id { get; set; }
        public string ExternalId { get; set; } = "";
        public string? CveId { get; set; }
        public string? Aliases { get; set; }
        public string? Title { get; set; }
        public string? Description { get; set; }
        public decimal? CvssScore { get; set; }
        public string? CvssVector { get; set; }
        public string? CvssVersion { get; set; }
        public string Severity { get; set; } = "";
        public bool InKev { get; set; }
        public DateTime? KevDateAdded { get; set; }
        public DateTime? KevDueDate { get; set; }
        public string? KevRansomware { get; set; }
        public string? KevRequiredAction { get; set; }
        public string? Cwe { get; set; }
        public string Source { get; set; } = "";
        public string? SourceStatus { get; set; }
        public string? Affected { get; set; }
        public string? ReferencesJson { get; set; }
        public DateTime? PublishedAt { get; set; }
        public DateTime? LastModifiedAt { get; set; }
    }

    private static int Priority(string source) => source switch { "NVD" => 3, "MITRE" => 2, "OSV" => 1, _ => 0 };

    /// <summary>
    /// Insère ou fusionne une faille. Priorité des métadonnées : NVD &gt; MITRE &gt; OSV.
    /// Les règles "affected" sont fusionnées par source (celles de la source entrante remplacent les anciennes).
    /// Retourne l'id, si c'est une nouvelle faille, et la liste fusionnée des règles.
    /// </summary>
    public async Task<(int Id, bool IsNew, List<AffectedRule> Rules)> UpsertAsync(NormalizedVulnerability v, CancellationToken ct)
    {
        await using var cn = await OpenAsync(ct);
        var existing = await cn.QueryFirstOrDefaultAsync<VulnRow>(
            "SELECT * FROM vulnerabilities WHERE external_id=@ExternalId OR (@CveId IS NOT NULL AND cve_id=@CveId) ORDER BY id LIMIT 1",
            new { v.ExternalId, v.CveId });

        var refs = JsonSerializer.Serialize(v.References.Select(r => new { url = r.Url, tags = r.Tags }));

        if (existing is null)
        {
            var id = await cn.ExecuteScalarAsync<int>("""
                INSERT INTO vulnerabilities (external_id, cve_id, aliases, title, description, cvss_score, cvss_vector, cvss_version,
                    severity, in_kev, kev_date_added, kev_due_date, kev_ransomware, kev_required_action, cwe, source, source_status,
                    affected, fixed_versions, references_json, published_at, last_modified_at)
                VALUES (@ExternalId, @CveId, @aliases, @title, @Description, @CvssScore, @CvssVector, @CvssVersion,
                    @Severity, @InKev, @KevDateAdded, @KevDueDate, @KevRansomware, @KevRequiredAction, @Cwe, @Source, @SourceStatus,
                    @affected, @fixed, @refs, @PublishedAt, @LastModifiedAt)
                RETURNING id;
                """, new
            {
                v.ExternalId, v.CveId, aliases = JsonSerializer.Serialize(v.Aliases), title = v.Title?.Trunc(500), v.Description,
                v.CvssScore, CvssVector = v.CvssVector?.Trunc(200), v.CvssVersion, v.Severity, v.InKev, v.KevDateAdded, v.KevDueDate,
                v.KevRansomware, v.KevRequiredAction, v.Cwe, v.Source, v.SourceStatus, affected = AffectedRule.Serialize(v.Affected),
                @fixed = v.FixedVersionsText(), refs, v.PublishedAt, v.LastModifiedAt
            });
            return (id, true, v.Affected);
        }

        // Fusion
        var incomingSources = v.Affected.Select(r => r.Source).ToHashSet();
        var rules = AffectedRule.Deserialize(existing.Affected).Where(r => !incomingSources.Contains(r.Source)).Concat(v.Affected)
            .GroupBy(r => r.Describe()).Select(g => g.First()).ToList();
        var aliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try { foreach (var a in JsonSerializer.Deserialize<List<string>>(existing.Aliases ?? "[]") ?? []) aliases.Add(a); } catch (JsonException) { }
        foreach (var a in v.Aliases) aliases.Add(a);
        aliases.Remove(existing.ExternalId);

        var wins = Priority(v.Source) >= Priority(existing.Source);
        T? Pick<T>(T? incoming, T? current) => wins ? (incoming ?? current) : (current ?? incoming);
        var merged = new NormalizedVulnerability { Affected = rules };

        await cn.ExecuteAsync("""
            UPDATE vulnerabilities SET cve_id=@cve, aliases=@aliases, title=@title, description=@description,
                cvss_score=@score, cvss_vector=@vector, cvss_version=@cvssVersion, severity=@severity,
                in_kev=@inKev, kev_date_added=@kevAdded, kev_due_date=@kevDue, kev_ransomware=@kevRansom, kev_required_action=@kevAction,
                cwe=@cwe, source=@source, source_status=@status, affected=@affected, fixed_versions=@fixed,
                references_json=@refs, published_at=@published, last_modified_at=@modified
            WHERE id=@id
            """, new
        {
            id = existing.Id,
            cve = existing.CveId ?? v.CveId,
            aliases = JsonSerializer.Serialize(aliases),
            title = Pick(v.Title, existing.Title)?.Trunc(500),
            description = Pick(v.Description, existing.Description),
            score = wins && v.CvssScore is not null ? v.CvssScore : existing.CvssScore ?? v.CvssScore,
            vector = (wins && v.CvssScore is not null ? v.CvssVector : existing.CvssVector ?? v.CvssVector)?.Trunc(200),
            cvssVersion = wins && v.CvssScore is not null ? v.CvssVersion : existing.CvssVersion ?? v.CvssVersion,
            severity = wins && v.Severity != Severity.Unknown ? v.Severity : existing.Severity is "" or Severity.Unknown ? v.Severity : existing.Severity,
            inKev = existing.InKev || v.InKev,
            kevAdded = Utc(v.KevDateAdded ?? existing.KevDateAdded),
            kevDue = Utc(v.KevDueDate ?? existing.KevDueDate),
            kevRansom = v.KevRansomware ?? existing.KevRansomware,
            kevAction = v.KevRequiredAction ?? existing.KevRequiredAction,
            cwe = Pick(v.Cwe, existing.Cwe),
            source = wins ? v.Source : existing.Source,
            status = Pick(v.SourceStatus, existing.SourceStatus),
            affected = AffectedRule.Serialize(rules),
            @fixed = merged.FixedVersionsText(),
            refs = wins && v.References.Count > 0 ? refs : existing.ReferencesJson ?? refs,
            published = Pick(v.PublishedAt, existing.PublishedAt),
            modified = Max(v.LastModifiedAt, existing.LastModifiedAt),
        });
        return (existing.Id, false, rules);
    }

    // Npgsql exige des DateTime UTC (les colonnes "date" relues sont de type Unspecified)
    private static DateTime? Utc(DateTime? d) => d is null ? null : d.Value.Kind == DateTimeKind.Utc ? d : DateTime.SpecifyKind(d.Value, DateTimeKind.Utc);

    private static DateTime? Max(DateTime? a, DateTime? b) => a is null ? b : b is null ? a : a > b ? a : b;

    public async Task<bool> LinkAsync(int vulnerabilityId, int technologyId, string matchSource, CorrelationMatch match, bool baseline, CancellationToken ct)
    {
        await using var cn = await OpenAsync(ct);
        var args = new { vulnerabilityId, technologyId, matchSource, conf = match.Confidence, rule = match.Rule.Trunc(500), fixedIn = match.FixedIn?.Trunc(100), baseline };
        var exists = await cn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerability_technology WHERE vulnerability_id=@vulnerabilityId AND technology_id=@technologyId", args) > 0;
        if (exists)
        {
            await cn.ExecuteAsync("""
                UPDATE vulnerability_technology SET confidence=@conf, matched_rule=@rule, fixed_version=@fixedIn
                WHERE vulnerability_id=@vulnerabilityId AND technology_id=@technologyId
                """, args);
            return false;
        }
        await cn.ExecuteAsync("""
            INSERT INTO vulnerability_technology (vulnerability_id, technology_id, match_source, confidence, matched_rule, fixed_version, is_baseline)
            VALUES (@vulnerabilityId, @technologyId, @matchSource, @conf, @rule, @fixedIn, @baseline)
            ON CONFLICT (vulnerability_id, technology_id) DO NOTHING
            """, args);
        return true;
    }

    /// <summary>Liens sans alerte "new" : auto-réparant si le backend était indisponible lors d'un scan précédent.</summary>
    public async Task<List<AlertIngestItem>> GetPendingAlertItemsAsync(int? technologyId, CancellationToken ct)
    {
        await using var cn = await OpenAsync(ct);
        return (await cn.QueryAsync<AlertIngestItem>("""
            SELECT vt.vulnerability_id, vt.technology_id, 'new' AS kind, vt.is_baseline, vt.confidence
            FROM vulnerability_technology vt
            LEFT JOIN alerts a ON a.vulnerability_id = vt.vulnerability_id AND a.technology_id = vt.technology_id AND a.kind = 'new'
            WHERE a.id IS NULL
            """ + (technologyId is null ? "" : " AND vt.technology_id = @technologyId") + " LIMIT 5000", new { technologyId })).ToList();
    }

    // ------------------------------------------------------------------ KEV

    private sealed class IdCve
    {
        public int Id { get; set; }
        public string CveId { get; set; } = "";
    }

    public async Task<HashSet<string>> GetKnownCveIdsAsync(CancellationToken ct)
    {
        await using var cn = await OpenAsync(ct);
        return (await cn.QueryAsync<string>("SELECT cve_id FROM vulnerabilities WHERE cve_id IS NOT NULL")).ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Failles en base, pas encore marquées KEV, mais présentes dans le catalogue : escalade.</summary>
    public async Task<List<(int Id, string CveId)>> GetNewlyKevAsync(IReadOnlyDictionary<string, KevEntry> catalog, CancellationToken ct)
    {
        await using var cn = await OpenAsync(ct);
        var rows = await cn.QueryAsync<IdCve>("SELECT id, cve_id FROM vulnerabilities WHERE NOT in_kev AND cve_id IS NOT NULL");
        return rows.Where(r => catalog.ContainsKey(r.CveId)).Select(r => (r.Id, r.CveId)).ToList();
    }

    public async Task SetKevAsync(int id, KevEntry k, CancellationToken ct)
    {
        await using var cn = await OpenAsync(ct);
        await cn.ExecuteAsync("""
            UPDATE vulnerabilities SET in_kev=true, kev_date_added=@DateAdded, kev_due_date=@DueDate, kev_required_action=@RequiredAction,
                   kev_ransomware=@KnownRansomwareCampaignUse, title=COALESCE(title, @VulnerabilityName)
            WHERE id=@id
            """, new { id, k.DateAdded, k.DueDate, k.RequiredAction, k.KnownRansomwareCampaignUse, k.VulnerabilityName });
    }

    public async Task<List<AlertIngestItem>> GetLinksForVulnerabilityAsync(int vulnerabilityId, string kind, CancellationToken ct)
    {
        await using var cn = await OpenAsync(ct);
        return (await cn.QueryAsync<AlertIngestItem>(
            "SELECT vulnerability_id, technology_id, @kind AS kind, false AS is_baseline, confidence FROM vulnerability_technology WHERE vulnerability_id=@vulnerabilityId",
            new { vulnerabilityId, kind })).ToList();
    }

    // ------------------------------------------------------------------ EPSS

    public async Task<List<string>> GetLinkedCveIdsAsync(CancellationToken ct)
    {
        await using var cn = await OpenAsync(ct);
        return (await cn.QueryAsync<string>("""
            SELECT DISTINCT v.cve_id FROM vulnerabilities v JOIN vulnerability_technology vt ON vt.vulnerability_id = v.id
            WHERE v.cve_id IS NOT NULL LIMIT 20000
            """)).ToList();
    }

    public async Task UpdateEpssAsync(IReadOnlyDictionary<string, (decimal Epss, decimal Percentile)> scores, CancellationToken ct)
    {
        if (scores.Count == 0) return;
        await using var cn = await OpenAsync(ct);
        await using var tx = await cn.BeginTransactionAsync(ct);
        foreach (var (cve, s) in scores)
            await cn.ExecuteAsync("UPDATE vulnerabilities SET epss_score=@e, epss_percentile=@p WHERE cve_id=@cve",
                new { e = s.Epss, p = s.Percentile, cve }, tx);
        await tx.CommitAsync(ct);
    }
}

public sealed class ScanStats
{
    public int TechnologiesScanned { get; set; }
    public int VulnsFetched { get; set; }
    public int VulnsNew { get; set; }
    public int LinksNew { get; set; }
    public int KevUpdates { get; set; }
}
