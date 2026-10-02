using Microsoft.Extensions.Options;
using Vigie.Scanner.Models;
using Vigie.Scanner.Sources;
using Vigie.Shared;

namespace Vigie.Scanner.Services;

public sealed record ScanRequest(string Trigger, int? TechnologyId);

/// <summary>État partagé, exposé par GET /status.</summary>
public sealed class ScanStatus
{
    public bool Running { get; set; }
    public string? CurrentTrigger { get; set; }
    public string? CurrentStep { get; set; }
    public DateTime? StartedAt { get; set; }
    public int? LastRunId { get; set; }
    public string? LastStatus { get; set; }
    public DateTime? LastFinishedAt { get; set; }
    public DateTime? NextScheduledAt { get; set; }
    public int Queued { get; set; }
}

/// <summary>
/// Déroulement d'un scan :
///  1. catalogue CISA KEV ;
///  2. pour chaque technologie : NVD + OSV -> enrichissement MITRE -> drapeaux KEV -> enregistrement
///     -> corrélation (produit + version) -> liens -> EPSS des nouvelles CVE -> appel backend (alertes/courriels) ;
///  3. escalades KEV (failles connues qui viennent d'entrer au catalogue) + CVE KEV manquantes ;
///  4. rafraîchissement EPSS de toutes les CVE liées.
/// Aucune action corrective n'est effectuée : collecte et information seulement.
/// </summary>
public sealed class ScanOrchestrator(
    ScanRepository repo,
    IEnumerable<ITechnologySource> sources,
    NvdSource nvd,
    MitreSource mitre,
    CisaKevSource kevSource,
    EpssSource epss,
    BackendClient backend,
    ScanStatus status,
    IOptionsMonitor<ScanOptions> scanOptions,
    IOptionsMonitor<SourcesOptions> sourceOptions,
    ILogger<ScanOrchestrator> logger)
{
    public async Task RunAsync(ScanRequest request, CancellationToken ct)
    {
        var log = new ScanLog(logger);
        var stats = new ScanStats();
        var startedUtc = DateTime.UtcNow;
        var runId = await repo.StartRunAsync(request.Trigger, ct);
        status.Running = true;
        status.CurrentTrigger = request.Trigger;
        status.StartedAt = startedUtc;
        status.LastRunId = runId;
        var finalStatus = "success";

        try
        {
            log.Info($"Scan #{runId} démarré ({request.Trigger}{(request.TechnologyId is null ? "" : $", technologie {request.TechnologyId}")})");
            var techs = await repo.GetTechnologiesAsync(request.TechnologyId, ct);
            log.Info($"{techs.Count} technologie(s) active(s) à analyser");

            // 1. KEV
            Dictionary<string, KevEntry>? kev = null;
            if (kevSource.Enabled)
            {
                status.CurrentStep = "Catalogue CISA KEV";
                try
                {
                    kev = await kevSource.FetchCatalogAsync(ct);
                    log.Info($"CISA KEV : {kev.Count} failles exploitées au catalogue");
                }
                catch (Exception ex) { log.Error("CISA KEV indisponible", ex); }
            }

            // 2. Technologies
            var mitreBudget = scanOptions.CurrentValue.MitreBudgetPerRun;
            foreach (var tech in techs)
            {
                ct.ThrowIfCancellationRequested();
                status.CurrentStep = $"{tech.Label} ({stats.TechnologiesScanned + 1}/{techs.Count})";
                mitreBudget = await ScanTechnologyAsync(tech, kev, runId, startedUtc, stats, log, mitreBudget, ct);
                stats.TechnologiesScanned++;
            }

            // 3. KEV : escalades et CVE exploitées manquantes
            if (kev is not null)
            {
                status.CurrentStep = "Escalades KEV";
                await ProcessKevAsync(kev, techs, runId, stats, log, ct);
            }

            // 4. EPSS
            if (epss.Enabled && request.TechnologyId is null)
            {
                status.CurrentStep = "Rafraîchissement EPSS";
                try
                {
                    var cves = await repo.GetLinkedCveIdsAsync(ct);
                    var scores = await epss.FetchAsync(cves, ct);
                    await repo.UpdateEpssAsync(scores, ct);
                    log.Info($"EPSS : {scores.Count} score(s) mis à jour");
                }
                catch (Exception ex) { log.Error("EPSS indisponible", ex); }
            }

            // Scan manuel : envoi du courriel de notification à la fin
            if (request.Trigger == "manual")
            {
                status.CurrentStep = "Envoi du courriel";
                try { await backend.NotifyAsync(ct); log.Info("Courriel de notification demandé (scan manuel)"); }
                catch (Exception ex) when (ex is not OperationCanceledException) { log.Error("Envoi du courriel en échec", ex); }
            }

            if (log.Errors > 0) finalStatus = "partial";
            log.Info($"Scan terminé : {stats.VulnsFetched} failles lues, {stats.VulnsNew} nouvelles en base, {stats.LinksNew} nouvelles corrélations, {stats.KevUpdates} escalades KEV");
        }
        catch (OperationCanceledException)
        {
            finalStatus = "failed";
            log.Error("Scan interrompu");
        }
        catch (Exception ex)
        {
            finalStatus = "failed";
            log.Error("Scan en échec", ex);
        }
        finally
        {
            await repo.FinishRunAsync(runId, finalStatus, stats, log.ToString());
            status.Running = false;
            status.CurrentStep = null;
            status.LastStatus = finalStatus;
            status.LastFinishedAt = DateTime.UtcNow;
        }
    }

    private async Task<int> ScanTechnologyAsync(ScanTechnology tech, Dictionary<string, KevEntry>? kev, int runId, DateTime startedUtc,
        ScanStats stats, ScanLog log, int mitreBudget, CancellationToken ct)
    {
        var baseline = tech.LastScannedAt is null;
        var lookback = sourceOptions.CurrentValue.Nvd.InitialLookbackDays;
        DateTime? since = baseline
            ? (lookback > 0 ? DateTime.UtcNow.AddDays(-lookback) : null)
            : DateTime.SpecifyKind(tech.LastScannedAt!.Value, DateTimeKind.Utc).AddDays(-1); // chevauchement de sécurité

        // Collecte (fusion des sources par identifiant)
        var found = new Dictionary<string, NormalizedVulnerability>(StringComparer.OrdinalIgnoreCase);
        var failed = false;
        foreach (var source in sources.Where(s => s.Enabled))
        {
            try
            {
                foreach (var v in await source.FetchAsync(tech, since, log, ct))
                {
                    if (found.TryGetValue(v.ExternalId, out var existing))
                    {
                        existing.Affected.AddRange(v.Affected);
                        existing.DirectPackageMatch |= v.DirectPackageMatch;
                        foreach (var a in v.Aliases) existing.Aliases.Add(a);
                        existing.CvssScore ??= v.CvssScore;
                    }
                    else found[v.ExternalId] = v;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                failed = true;
                log.Error($"{source.Name} en échec pour {tech.Label}", ex);
            }
        }
        stats.VulnsFetched += found.Count;

        var newCves = new List<string>();
        var keywordMode = string.IsNullOrEmpty(tech.Vendor) && string.IsNullOrEmpty(tech.Ecosystem);
        var linksNew = 0;

        foreach (var v in found.Values)
        {
            // Enrichissement MITRE (CVE pas encore analysées par le NVD)
            if (mitre.Enabled && mitreBudget > 0 && MitreSource.NeedsEnrichment(v))
            {
                mitreBudget--;
                try { await mitre.EnrichAsync(v, ct); }
                catch (Exception ex) when (ex is not OperationCanceledException) { log.Error($"MITRE {v.CveId}", ex); }
            }

            if (kev is not null && v.CveId is not null && kev.TryGetValue(v.CveId, out var k)) k.ApplyTo(v);

            var (vid, isNew, rules) = await repo.UpsertAsync(v, ct);
            if (isNew) { stats.VulnsNew++; if (v.CveId is not null) newCves.Add(v.CveId); }

            var match = Correlator.Match(tech, rules);
            var matchSource = match?.Source switch { "OSV" => "OSV", "MITRE" => "MITRE", _ => "NVD_CPE" };

            if (match is null && v.DirectPackageMatch)
            {
                match = new CorrelationMatch(MatchConfidence.Confirmed, $"OSV : {tech.Ecosystem}/{tech.PackageName} {tech.Version} déclarée affectée",
                    "OSV", rules.Where(r => r.Kind == "pkg").Select(r => r.EndExcluding).FirstOrDefault(f => f is not null));
                matchSource = "OSV";
            }
            if (match is null && keywordMode && rules.All(r => r.Source != "NVD")
                && (v.Description?.Contains(tech.Name, StringComparison.OrdinalIgnoreCase) ?? false))
            {
                match = new CorrelationMatch(MatchConfidence.Probable, $"Mot-clé « {tech.Name} » dans la description (CVE non analysée)", "NVD", null);
                matchSource = "KEYWORD";
            }
            if (match is null) continue;

            if (await repo.LinkAsync(vid, tech.Id, matchSource, match, baseline, ct)) linksNew++;
        }
        stats.LinksNew += linksNew;

        // EPSS des nouvelles CVE avant la création des alertes (entre dans le calcul du risque)
        if (epss.Enabled && newCves.Count > 0)
        {
            try { await repo.UpdateEpssAsync(await epss.FetchAsync(newCves, ct), ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.Error("EPSS", ex); }
        }

        // Alertes (inclut les liens restés sans alerte lors d'un scan précédent)
        var pending = await repo.GetPendingAlertItemsAsync(tech.Id, ct);
        if (pending.Count > 0)
        {
            var created = await backend.IngestAsync(runId, pending, ct);
            log.Info($"{tech.Label} : {linksNew} nouvelle(s) corrélation(s), {created} alerte(s) créée(s){(baseline ? " [inventaire initial]" : "")}");
        }
        else if (linksNew == 0) log.Info($"{tech.Label} : rien de nouveau");

        if (!failed) await repo.MarkScannedAsync(tech.Id, startedUtc, ct);
        return mitreBudget;
    }

    private async Task ProcessKevAsync(Dictionary<string, KevEntry> kev, List<ScanTechnology> techs, int runId, ScanStats stats, ScanLog log, CancellationToken ct)
    {
        // a) Failles déjà en base qui viennent d'entrer au catalogue -> alerte d'escalade "kev"
        var escalations = new List<AlertIngestItem>();
        foreach (var (id, cve) in await repo.GetNewlyKevAsync(kev, ct))
        {
            await repo.SetKevAsync(id, kev[cve], ct);
            var links = await repo.GetLinksForVulnerabilityAsync(id, "kev", ct);
            escalations.AddRange(links);
            if (links.Count > 0) { stats.KevUpdates++; log.Info($"KEV : {cve} est maintenant exploitée activement ({links.Count} technologie(s))"); }
        }
        if (escalations.Count > 0) await backend.IngestAsync(runId, escalations, ct);

        // b) CVE exploitées qui pourraient concerner la stack et absentes de la base
        if (!nvd.Enabled || techs.Count == 0) return;
        var known = await repo.GetKnownCveIdsAsync(ct);
        var candidates = kev.Values
            .Where(k => !known.Contains(k.CveId))
            .Select(k => (Entry: k, Techs: techs.Where(t => CisaKevSource.MightConcern(k, t)).ToList()))
            .Where(x => x.Techs.Count > 0)
            .OrderByDescending(x => x.Entry.DateAdded)
            .Take(scanOptions.CurrentValue.KevFetchBudgetPerRun)
            .ToList();
        if (candidates.Count == 0) return;

        status.CurrentStep = $"KEV : {candidates.Count} CVE exploitée(s) à vérifier";
        var touched = new HashSet<int>();
        foreach (var (entry, concerned) in candidates)
        {
            try
            {
                var v = await nvd.GetByCveAsync(entry.CveId, ct);
                if (v is null) continue;
                if (mitre.Enabled && MitreSource.NeedsEnrichment(v)) await mitre.EnrichAsync(v, ct);
                entry.ApplyTo(v);
                var (vid, isNew, rules) = await repo.UpsertAsync(v, ct);
                if (isNew) stats.VulnsNew++;
                foreach (var t in concerned)
                {
                    var match = Correlator.Match(t, rules);
                    if (match is null) continue;
                    var src = match.Source switch { "MITRE" => "MITRE", _ => "KEV" };
                    if (await repo.LinkAsync(vid, t.Id, src, match, t.LastScannedAt is null, ct)) { stats.LinksNew++; touched.Add(t.Id); }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.Error($"KEV {entry.CveId}", ex); }
        }

        foreach (var tid in touched)
            await backend.IngestAsync(runId, await repo.GetPendingAlertItemsAsync(tid, ct), ct);
        log.Info($"KEV : {candidates.Count} CVE exploitée(s) vérifiée(s), {touched.Count} technologie(s) concernée(s)");
    }
}
