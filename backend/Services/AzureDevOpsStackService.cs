using System.Text;
using Vigie.Api.Models;
using Vigie.Shared;

namespace Vigie.Api.Services;

/// <summary>Construit la stack de chaque solution à partir des dépôts Azure DevOps (une solution = un ou plusieurs dépôts).</summary>
public sealed class AzureDevOpsStackService(AzureDevOpsClient client, ILogger<AzureDevOpsStackService> logger)
{
    public bool Configured => client.Configured;

    public async Task<List<AzdoRepoInfo>> ListRepositoriesAsync(CancellationToken ct)
    {
        var repos = new List<AzdoRepoInfo>();
        foreach (var project in await client.ListProjectsAsync(ct))
        {
            if (await client.GetSourceControlTypeAsync(project, ct) == "Tfvc")
            {
                // Projet TFVC : la racine entière, puis chaque dossier de premier niveau (souvent une solution ou "Main")
                repos.Add(new AzdoRepoInfo { Project = project, Name = $"$/{project}", SuggestedSolution = project, Kind = "tfvc" });
                foreach (var folder in await client.ListTfvcFoldersAsync(project, ct))
                    repos.Add(new AzdoRepoInfo { Project = project, Name = folder, SuggestedSolution = folder.Split('/').Last(), Kind = "tfvc" });
                continue;
            }
            foreach (var r in await client.ListReposAsync(project, ct))
                repos.Add(new AzdoRepoInfo { Project = r.Project, Name = r.Name, DefaultBranch = r.DefaultBranch, SuggestedSolution = r.Name });
        }
        return repos;
    }

    public async Task<AzdoScanResult> ScanAsync(IEnumerable<AzdoScanTarget> targets, CancellationToken ct)
    {
        var result = new AzdoScanResult();
        var bySolution = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var t in targets)
        {
            var solution = string.IsNullOrWhiteSpace(t.Solution) ? t.Repo : t.Solution.Trim();
            var rr = new AzdoRepoResult { Project = t.Project, Repo = t.Repo, Solution = solution };
            result.Repos.Add(rr);
            try
            {
                var tfvc = t.Kind.Equals("tfvc", StringComparison.OrdinalIgnoreCase);
                string? branch = null;
                List<string>? paths;
                if (tfvc) paths = await client.ListTfvcFilesAsync(t.Project, t.Repo, ct);
                else (branch, paths) = await FindBranchAsync(t, ct);
                rr.Branch = tfvc ? "TFVC" : branch;
                if (paths is null) { rr.Error = tfvc ? "Dossier TFVC introuvable." : "Branche introuvable ou dépôt vide."; continue; }

                var parsed = await StackManifestParser.AnalyzeAsync(paths, async p => tfvc
                    ? await client.GetTfvcFileAsync(t.Project, p, ct)
                    : await client.GetFileAsync(t.Project, t.Repo, branch!, p, ct));
                rr.Files = parsed.Files;
                rr.Warnings = parsed.Warnings;
                rr.Technologies = parsed.Lines.Count;
                if (parsed.Files.Count == 0) rr.Warnings.Add("Aucun fichier de dépendances reconnu.");

                if (!bySolution.TryGetValue(solution, out var lines)) bySolution[solution] = lines = new(StringComparer.OrdinalIgnoreCase);
                lines.UnionWith(parsed.Lines);
            }
            catch (InvalidOperationException ex) { rr.Error = ex.Message; }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
            {
                logger.LogWarning(ex, "Lecture du dépôt {Repo} impossible", t.Repo);
                rr.Error = "Azure DevOps est injoignable ou a mis trop de temps à répondre.";
            }
        }

        foreach (var (solution, lines) in bySolution) KeepHighestVersions(solution, lines, result);
        result.Text = BuildText(bySolution);
        return result;
    }

    /// <summary>
    /// Un même paquet en plusieurs versions dans une solution (plusieurs package.json…) : l'import n'en garderait qu'une
    /// (la dernière lue), on garde donc la plus haute, la plus prudente pour la mise à jour, et on le signale.
    /// </summary>
    private static void KeepHighestVersions(string solution, HashSet<string> lines, AzdoScanResult result)
    {
        var groups = lines.Select(l => (Line: l, At: l.LastIndexOf('@'))).Where(x => x.At > 0)
            .GroupBy(x => x.Line[..x.At], StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1);
        foreach (var g in groups)
        {
            var keep = g.Select(x => x.Line).Aggregate((a, b) => VersionComparer.Compare(a[(a.LastIndexOf('@') + 1)..], b[(b.LastIndexOf('@') + 1)..]) >= 0 ? a : b);
            foreach (var x in g.Where(x => x.Line != keep)) lines.Remove(x.Line);
            var msg = $"{g.Key} en plusieurs versions ({string.Join(", ", g.Select(x => x.Line[(x.At + 1)..]))}) : seule {keep[(keep.LastIndexOf('@') + 1)..]} est conservée pour la solution.";
            result.Repos.First(r => r.Solution.Equals(solution, StringComparison.OrdinalIgnoreCase) && r.Error is null).Warnings.Add(msg);
        }
    }

    /// <summary>Branche demandée, sinon celle par défaut du dépôt, sinon main puis master.</summary>
    private async Task<(string? Branch, List<string>? Paths)> FindBranchAsync(AzdoScanTarget t, CancellationToken ct)
    {
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(t.Branch)) candidates.Add(t.Branch.Trim());
        else
        {
            var def = (await client.ListReposAsync(t.Project, ct)).FirstOrDefault(r => r.Name.Equals(t.Repo, StringComparison.OrdinalIgnoreCase))?.DefaultBranch;
            if (def is not null) candidates.Add(def);
            candidates.AddRange(["main", "master"]);
        }
        foreach (var b in candidates.Distinct())
            if (await client.ListFilesAsync(t.Project, t.Repo, b, ct) is { } paths) return (b, paths);
        return (candidates.FirstOrDefault(), null);
    }

    private static string BuildText(Dictionary<string, HashSet<string>> bySolution)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Stack déduite des dépôts Azure DevOps — à vérifier avec « Prévisualiser » avant d'importer.");
        foreach (var (solution, lines) in bySolution.OrderBy(s => s.Key, StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine().AppendLine($"[{solution}]");
            foreach (var l in lines.OrderBy(Order).ThenBy(l => l, StringComparer.OrdinalIgnoreCase)) sb.AppendLine(l);
        }
        return sb.ToString();
    }

    // Runtimes et frameworks d'abord, puis images Docker, puis paquets
    private static int Order(string line) =>
        line.StartsWith("runtime:") ? 0 : line.StartsWith("framework:") ? 1 : line.StartsWith("docker:") ? 2 : 3;
}
