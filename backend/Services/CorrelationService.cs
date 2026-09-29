using Dapper;
using Vigie.Api.Data;
using Vigie.Api.Models;
using Vigie.Shared;

namespace Vigie.Api.Services;

public sealed record CorrelationSummary(int Evaluated, int Linked, int Unlinked, int AlertsCreated, int AlertsResolved);

/// <summary>
/// Corrélation vulnérabilités &lt;-&gt; technologies à partir des règles "affected"
/// déjà stockées (utile quand on ajoute une technologie ou qu'on change sa version,
/// sans attendre le prochain scan).
/// </summary>
public sealed class CorrelationService(Db db, AlertService alerts, ILogger<CorrelationService> logger)
{
    private sealed class Candidate
    {
        public int Id { get; set; }
        public string? Affected { get; set; }
    }

    private sealed class ExistingLink
    {
        public int VulnerabilityId { get; set; }
        public string MatchSource { get; set; } = "";
    }

    public async Task<CorrelationSummary> RecorrelateTechnologyAsync(Technology tech, bool baseline)
    {
        await using var cn = await db.OpenAsync();

        // Pré-filtre SQL grossier, filtrage exact en C# (Correlator)
        var patterns = new List<string> { $"%{tech.Product}%" };
        if (!string.IsNullOrEmpty(tech.PackageName)) patterns.Add($"%{tech.PackageName}%");
        var where = string.Join(" OR ", patterns.Select((_, i) => $"affected ILIKE @p{i}"));
        var args = new DynamicParameters();
        for (var i = 0; i < patterns.Count; i++) args.Add($"p{i}", patterns[i]);

        args.Add("tid", tech.Id);

        // Candidates = failles qui mentionnent le produit + failles déjà liées (pour détecter les liens qui ne tiennent plus)
        var candidates = (await cn.QueryAsync<Candidate>($"""
            SELECT id, affected FROM vulnerabilities WHERE {where}
            UNION
            SELECT v.id, v.affected FROM vulnerabilities v
              JOIN vulnerability_technology vt ON vt.vulnerability_id = v.id AND vt.technology_id = @tid
            """, args)).ToList();
        var existing = (await cn.QueryAsync<ExistingLink>(
            "SELECT vulnerability_id, match_source FROM vulnerability_technology WHERE technology_id=@id", new { id = tech.Id }))
            .ToDictionary(x => x.VulnerabilityId);

        var toAlert = new List<AlertIngestItem>();
        var linked = 0;
        var unlinked = 0;
        var resolved = 0;
        var matchedIds = new HashSet<int>();

        foreach (var c in candidates)
        {
            var rules = AffectedRule.Deserialize(c.Affected);
            var match = Correlator.Match(tech, rules);
            if (match is null) continue;
            matchedIds.Add(c.Id);

            await cn.ExecuteAsync("""
                INSERT INTO vulnerability_technology (vulnerability_id, technology_id, match_source, confidence, matched_rule, fixed_version, is_baseline)
                VALUES (@vid, @tid, @src, @conf, @rule, @fixedIn, @baseline)
                ON CONFLICT (vulnerability_id, technology_id) DO UPDATE
                SET confidence=EXCLUDED.confidence, matched_rule=EXCLUDED.matched_rule, fixed_version=EXCLUDED.fixed_version
                """, new { vid = c.Id, tid = tech.Id, src = match.Source == "OSV" ? "OSV" : match.Source == "MITRE" ? "MITRE" : "NVD_CPE",
                           conf = match.Confidence, rule = Trunc(match.Rule, 500), fixedIn = match.FixedIn, baseline });

            if (!existing.ContainsKey(c.Id))
            {
                linked++;
                toAlert.Add(new AlertIngestItem { VulnerabilityId = c.Id, TechnologyId = tech.Id, IsBaseline = baseline, Confidence = match.Confidence });
            }
        }

        // Liens qui ne tiennent plus (version mise à jour) : suppression + résolution des alertes ouvertes
        foreach (var (vid, link) in existing)
        {
            if (matchedIds.Contains(vid) || link.MatchSource == "KEYWORD") continue;

            await cn.ExecuteAsync("DELETE FROM vulnerability_technology WHERE vulnerability_id=@vid AND technology_id=@tid", new { vid, tid = tech.Id });
            resolved += await cn.ExecuteAsync("""
                UPDATE alerts SET status='resolved', status_changed_at=now(),
                       status_comment=@comment
                WHERE vulnerability_id=@vid AND technology_id=@tid AND status IN ('new','acknowledged')
                """, new { vid, tid = tech.Id, comment = $"Résolue automatiquement : la version {tech.Version} n'est plus dans la plage vulnérable" });
            unlinked++;
        }

        var created = toAlert.Count > 0 ? (await alerts.IngestAsync(new AlertIngestRequest { Items = toAlert })).Created : 0;
        logger.LogInformation("Corrélation {Tech} {Version} : {Eval} candidates, +{Linked} / -{Unlinked} liens, {Created} alertes, {Resolved} résolues",
            tech.Name, tech.Version, candidates.Count, linked, unlinked, created, resolved);
        return new CorrelationSummary(candidates.Count, linked, unlinked, created, resolved);
    }

    private static string Trunc(string s, int max) => s.Length <= max ? s : s[..max];
}
