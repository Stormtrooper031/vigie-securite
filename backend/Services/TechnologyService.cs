using Dapper;
using Npgsql;
using Vigie.Api.Data;
using Vigie.Api.Models;
using Vigie.Shared;

namespace Vigie.Api.Services;

/// <summary>Gestion de la stack : CRUD, normalisation, import en lot.</summary>
public sealed class TechnologyService(Db db, CorrelationService correlation, ScannerClient scanner, ILogger<TechnologyService> logger)
{
    private const string SelectWithCounts = """
        SELECT t.*,
               (SELECT COUNT(*) FROM vulnerability_technology vt WHERE vt.technology_id = t.id) AS vulnerability_count,
               (SELECT COUNT(*) FROM alerts a WHERE a.technology_id = t.id AND a.status IN ('new','acknowledged')) AS open_alert_count,
               (SELECT a.severity FROM alerts a WHERE a.technology_id = t.id AND a.status IN ('new','acknowledged')
                 ORDER BY severity_rank(a.severity) DESC LIMIT 1) AS max_severity
        FROM technologies t
        """;

    public async Task<List<Technology>> ListAsync(bool? active = null)
    {
        await using var cn = await db.OpenAsync();
        var sql = SelectWithCounts + (active is null ? "" : " WHERE t.is_active = @active") + " ORDER BY t.type, t.name";
        return (await cn.QueryAsync<Technology>(sql, new { active })).ToList();
    }

    public async Task<Technology?> GetAsync(int id)
    {
        await using var cn = await db.OpenAsync();
        return await cn.QuerySingleOrDefaultAsync<Technology>(SelectWithCounts + " WHERE t.id = @id", new { id });
    }

    private sealed class UpdateRow
    {
        public int TechnologyId { get; set; }
        public string Name { get; set; } = "";
        public string Type { get; set; } = "";
        public string Version { get; set; } = "";
        public string? FixedVersion { get; set; }
        public string Severity { get; set; } = "";
        public bool InKev { get; set; }
        public string ExternalId { get; set; } = "";
        public int RiskScore { get; set; }
    }

    /// <summary>Liste des mises à jour à faire, par technologie, triée par urgence.</summary>
    public async Task<List<TechnologyUpdate>> GetUpdatesAsync()
    {
        await using var cn = await db.OpenAsync();
        var rows = await cn.QueryAsync<UpdateRow>("""
            SELECT t.id AS technology_id, t.name, t.type, t.version, vt.fixed_version, a.severity, v.in_kev,
                   COALESCE(v.cve_id, v.external_id) AS external_id, a.risk_score
            FROM alerts a
            JOIN technologies t ON t.id = a.technology_id AND t.is_active
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            LEFT JOIN vulnerability_technology vt ON vt.vulnerability_id = a.vulnerability_id AND vt.technology_id = a.technology_id
            WHERE a.status IN ('new','acknowledged') AND a.kind = 'new'
            """);

        return rows.GroupBy(r => r.TechnologyId).Select(g =>
        {
            var first = g.First();
            var fixes = g.Select(r => r.FixedVersion).Where(f => !string.IsNullOrWhiteSpace(f)).Distinct().ToList();
            var recommended = fixes.Count == 0 ? null : fixes.Aggregate((a, b) => VersionComparer.Compare(a, b) >= 0 ? a : b);
            return new TechnologyUpdate
            {
                TechnologyId = g.Key, Name = first.Name, Type = first.Type, CurrentVersion = first.Version,
                RecommendedVersion = recommended,
                MaxSeverity = g.Select(r => r.Severity).Aggregate(Severity.Max),
                OpenAlerts = g.Count(),
                Critical = g.Count(r => r.Severity == Severity.Critical),
                High = g.Count(r => r.Severity == Severity.High),
                Kev = g.Count(r => r.InKev),
                WithoutFix = g.Count(r => string.IsNullOrWhiteSpace(r.FixedVersion)),
                TopCves = g.OrderByDescending(r => r.RiskScore).Take(5).Select(r => r.ExternalId).ToList()
            };
        })
        .OrderByDescending(u => Severity.Rank(u.MaxSeverity)).ThenByDescending(u => u.Kev).ThenByDescending(u => u.Critical).ThenByDescending(u => u.OpenAlerts)
        .ToList();
    }

    private static readonly (string Type, string Title)[] ExportSections =
    [
        (TechTypes.Os, "Systèmes d'exploitation"), (TechTypes.WebServer, "Serveurs web"),
        (TechTypes.Runtime, "Runtimes"), (TechTypes.Framework, "Frameworks"), (TechTypes.Database, "Bases de données"),
        (TechTypes.Application, "Applications"), (TechTypes.Library, "Bibliothèques et paquets"),
        (TechTypes.DockerImage, "Images Docker"), (TechTypes.Other, "Autres"),
    ];

    /// <summary>
    /// Export de la stack au format config/stack.txt (réimportable tel quel). Les technologies sans
    /// solution viennent en tête, puis une section "[Solution]" par solution (une technologie partagée
    /// figure dans chacune). Les inactives sont en commentaire ; les notes en commentaire au-dessus.
    /// </summary>
    public async Task<string> ExportAsync()
    {
        var techs = await ListAsync();
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("# =====================================================================");
        sb.AppendLine($"#  Stack exportée de Vigie Sécurité le {DateTime.Now:yyyy-MM-dd HH:mm}");
        sb.AppendLine($"#  {techs.Count(t => t.IsActive)} technologie(s) active(s), {techs.Count(t => !t.IsActive)} inactive(s) (en commentaire).");
        sb.AppendLine("#  Format :  [préfixe:]nom[@version]  [| option=valeur | ...]");
        sb.AppendLine("#  Une ligne [Solution] affecte les lignes suivantes à cette solution.");
        sb.AppendLine("#  Réimportable via la page « Ma stack » ou en remplaçant config/stack.txt.");
        sb.AppendLine("# =====================================================================");

        AppendByType(sb, techs.Where(t => t.Solutions.Length == 0).ToList());
        foreach (var solution in techs.SelectMany(t => t.Solutions).DistinctBy(s => s.ToLowerInvariant()).Order(StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine().AppendLine().AppendLine($"[{solution}]");
            AppendByType(sb, techs.Where(t => HasSolution(t.Solutions, solution)).ToList());
        }
        return sb.ToString();
    }

    private static void AppendByType(System.Text.StringBuilder sb, List<Technology> techs)
    {
        var sections = ExportSections.Select(s => s.Type).ToHashSet();
        foreach (var (type, title) in ExportSections)
        {
            var group = techs.Where(t => t.Type == type || (type == TechTypes.Other && !sections.Contains(t.Type))).ToList();
            if (group.Count == 0) continue;
            sb.AppendLine().AppendLine($"# --- {title} ---");
            foreach (var t in group.OrderBy(t => t.Ecosystem).ThenBy(t => t.Name, StringComparer.OrdinalIgnoreCase))
            {
                string line;
                try
                {
                    line = TechnologyNormalizer.ToLine(t.Name, t.Type, t.Vendor, t.Product, t.Version,
                        t.Ecosystem, t.PackageName, t.Cpe, t.Keywords);
                }
                catch (FormatException ex)
                {
                    sb.AppendLine($"# ERREUR (technologie {t.Id} « {t.Name} ») : {ex.Message}");
                    continue;
                }
                if (!string.IsNullOrWhiteSpace(t.Notes)) sb.AppendLine($"# {t.Notes.ReplaceLineEndings(" ")}");
                sb.AppendLine(t.IsActive ? line : $"# (inactive) {line}");
            }
        }
    }

    public NormalizedTechnology Normalize(TechnologyInput input) =>
        TechnologyNormalizer.FromFields(input.Name, input.Type, input.Vendor, input.Product, input.Version,
            input.Ecosystem, input.PackageName, input.Cpe, input.Keywords);

    public async Task<Technology> CreateAsync(TechnologyInput input)
    {
        if (string.IsNullOrWhiteSpace(input.Name)) throw new ArgumentException("Le nom est obligatoire.");
        var n = Normalize(input);
        int id;
        await using (var cn = await db.OpenAsync())
        {
            try
            {
                id = await cn.ExecuteScalarAsync<int>("""
                    INSERT INTO technologies (name, type, vendor, product, version, ecosystem, package_name, cpe, keywords, source_line, is_active, notes, solutions)
                    VALUES (@Name, @Type, @Vendor, @Product, @Version, @Ecosystem, @PackageName, @Cpe, @Keywords, @SourceLine, @IsActive, @Notes, @solutions)
                    RETURNING id;
                    """, new { n.Name, n.Type, n.Vendor, n.Product, n.Version, n.Ecosystem, n.PackageName, n.Cpe, n.Keywords, n.SourceLine, input.IsActive, input.Notes,
                               solutions = InputSolutions(input) ?? [] });
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                throw new InvalidOperationException("Cette technologie (même produit, version et écosystème) existe déjà.");
            }
        }

        var tech = (await GetAsync(id))!;
        await AfterChangeAsync(tech);
        return (await GetAsync(id))!;
    }

    public async Task<Technology?> UpdateAsync(int id, TechnologyInput input)
    {
        var before = await GetAsync(id);
        if (before is null) return null;
        var n = Normalize(input);

        // Produit ou version modifié : nouvel inventaire complet au prochain scan
        var identityChanged = before.Product != n.Product || before.Vendor != n.Vendor || before.Version != n.Version
                              || before.Ecosystem != n.Ecosystem || before.PackageName != n.PackageName;

        await using (var cn = await db.OpenAsync())
        {
            await cn.ExecuteAsync("""
                UPDATE technologies SET name=@Name, type=@Type, vendor=@Vendor, product=@Product, version=@Version,
                       ecosystem=@Ecosystem, package_name=@PackageName, cpe=@Cpe, keywords=@Keywords, is_active=@IsActive,
                       notes=@Notes, solutions=@solutions, last_scanned_at = CASE WHEN @identityChanged THEN NULL ELSE last_scanned_at END
                WHERE id=@id
                """, new { n.Name, n.Type, n.Vendor, n.Product, n.Version, n.Ecosystem, n.PackageName, n.Cpe, n.Keywords,
                           input.IsActive, input.Notes, solutions = InputSolutions(input) ?? before.Solutions, identityChanged, id });
        }

        var tech = (await GetAsync(id))!;
        if (identityChanged) await AfterChangeAsync(tech);
        return await GetAsync(id);
    }

    public async Task<bool> DeleteAsync(int id)
    {
        await using var cn = await db.OpenAsync();
        return await cn.ExecuteAsync("DELETE FROM technologies WHERE id=@id", new { id }) > 0;
    }

    public async Task<bool> RequestRescanAsync(int id)
    {
        await using (var cn = await db.OpenAsync())
        {
            if (await cn.ExecuteAsync("UPDATE technologies SET last_scanned_at = NULL WHERE id=@id", new { id }) == 0) return false;
        }
        await scanner.TriggerAsync(id);
        return true;
    }

    /// <summary>
    /// Après ajout / changement de version : corrélation immédiate avec les failles déjà connues
    /// (les alertes des versions qui ne sont plus touchées sont résolues automatiquement),
    /// puis demande de scan ciblé au service de surveillance.
    /// </summary>
    private async Task AfterChangeAsync(Technology tech)
    {
        try
        {
            await correlation.RecorrelateTechnologyAsync(tech, baseline: true);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Corrélation impossible pour la technologie {Id}", tech.Id);
        }
        if (tech.IsActive) _ = scanner.TriggerAsync(tech.Id);
    }

    /// <summary>
    /// Import d'une liste (format config/stack.txt). Règle de rapprochement :
    ///  - même produit + même version : inchangé (ou mise à jour du nom/type) ; la solution est ajoutée ;
    ///  - une seule entrée du même produit avec une autre version, dans la même solution (ou sans solution) :
    ///    mise à jour de la version ;
    ///  - sinon : création (une entrée partagée avec d'autres solutions leur est laissée).
    /// </summary>
    public async Task<TechnologyImportResult> ImportAsync(string text, bool dryRun, bool triggerScan = true)
    {
        var result = new TechnologyImportResult();
        var parsed = TechnologyNormalizer.ParseMany(text);
        var changed = new List<int>();

        await using var cn = await db.OpenAsync();
        foreach (var (lineNo, n, error) in parsed)
        {
            var line = new TechnologyImportLine { Line = lineNo, Normalized = n, Source = n?.SourceLine, Error = error };
            result.Lines.Add(line);
            if (n is null) { line.Status = "error"; continue; }
            if (dryRun) { line.Status = "preview"; continue; }

            var sameProduct = (await cn.QueryAsync<Technology>("""
                SELECT * FROM technologies
                WHERE type=@Type AND vendor=@Vendor AND product=@Product AND ecosystem=@Ecosystem
                """, new { n.Type, n.Vendor, n.Product, n.Ecosystem })).ToList();

            // Même produit + même version : une seule technologie, partagée entre les solutions (pas d'alertes en double)
            var exact = sameProduct.FirstOrDefault(t => t.Version == n.Version);
            if (exact is not null)
            {
                line.TechnologyId = exact.Id;
                var solutions = MergeSolutions(exact.Solutions, n.Solutions);
                if (exact.Name != n.Name || exact.Cpe != n.Cpe || exact.Keywords != n.Keywords || !solutions.SequenceEqual(exact.Solutions))
                {
                    await cn.ExecuteAsync("UPDATE technologies SET name=@Name, cpe=@Cpe, keywords=@Keywords, source_line=@SourceLine, solutions=@solutions WHERE id=@id",
                        new { n.Name, n.Cpe, n.Keywords, n.SourceLine, solutions, id = exact.Id });
                    line.Status = "updated"; result.Updated++;
                }
                else { line.Status = "unchanged"; result.Unchanged++; }
                continue;
            }

            // Autre version : on ne met à jour que l'entrée de la même solution (ou sans solution),
            // jamais celle d'une autre solution qui peut rester sur l'ancienne version.
            var candidates = n.Solutions.Length == 0
                ? sameProduct
                : sameProduct.Where(t => t.Solutions.Length == 0 || t.Solutions.Any(s => HasSolution(n.Solutions, s))).ToList();
            if (candidates.Count == 1)
            {
                var old = candidates[0];
                var others = old.Solutions.Where(s => !HasSolution(n.Solutions, s)).ToArray();
                if (n.Solutions.Length > 0 && others.Length > 0)
                {
                    // Partagée avec d'autres solutions : on la leur laisse et on crée l'entrée de cette solution
                    await cn.ExecuteAsync("UPDATE technologies SET solutions=@others WHERE id=@id", new { others, id = old.Id });
                }
                else
                {
                    await cn.ExecuteAsync("""
                        UPDATE technologies SET name=@Name, version=@Version, cpe=@Cpe, keywords=@Keywords, package_name=@PackageName,
                               source_line=@SourceLine, solutions=@solutions, last_scanned_at=NULL WHERE id=@id
                        """, new { n.Name, n.Version, n.Cpe, n.Keywords, n.PackageName, n.SourceLine,
                                   solutions = MergeSolutions(old.Solutions, n.Solutions), id = old.Id });
                    line.TechnologyId = old.Id; line.Status = "updated"; result.Updated++;
                    changed.Add(old.Id);
                    continue;
                }
            }

            try
            {
                var id = await cn.ExecuteScalarAsync<int>("""
                    INSERT INTO technologies (name, type, vendor, product, version, ecosystem, package_name, cpe, keywords, source_line, solutions)
                    VALUES (@Name, @Type, @Vendor, @Product, @Version, @Ecosystem, @PackageName, @Cpe, @Keywords, @SourceLine, @Solutions)
                    RETURNING id;
                    """, new { n.Name, n.Type, n.Vendor, n.Product, n.Version, n.Ecosystem, n.PackageName, n.Cpe, n.Keywords, n.SourceLine, n.Solutions });
                line.TechnologyId = id; line.Status = "created"; result.Created++;
                changed.Add(id);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                line.Status = "error";
                line.Error = "Doublon : même produit, version et écosystème qu'une autre ligne";
            }
        }

        foreach (var id in changed)
        {
            var tech = await GetAsync(id);
            if (tech is null) continue;
            try { await correlation.RecorrelateTechnologyAsync(tech, baseline: true); }
            catch (Exception ex) { logger.LogError(ex, "Corrélation impossible pour {Id}", id); }
        }
        if (changed.Count > 0 && triggerScan) _ = scanner.TriggerAsync(null);
        return result;
    }

    /// <summary>Solutions saisies au formulaire, nettoyées ; null = champ absent (on garde l'existant).</summary>
    private static string[]? InputSolutions(TechnologyInput input) =>
        input.Solutions is null ? null : TechnologyNormalizer.ParseSolutions(string.Join(",", input.Solutions));

    private static bool HasSolution(IEnumerable<string> solutions, string s) =>
        solutions.Contains(s, StringComparer.OrdinalIgnoreCase);

    /// <summary>Union sans doublon (insensible à la casse), dans l'ordre : existantes puis nouvelles.</summary>
    private static string[] MergeSolutions(string[] existing, string[] added) =>
        existing.Concat(added).DistinctBy(s => s.ToLowerInvariant()).ToArray();
}
