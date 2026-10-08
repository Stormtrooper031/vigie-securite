using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Vigie.Api.Models;

namespace Vigie.Api.Services;

/// <summary>Lecture seule de l'API REST Azure DevOps Services (dev.azure.com) avec un PAT.</summary>
public sealed class AzureDevOpsClient
{
    private const string ApiVersion = "api-version=7.1";
    private readonly HttpClient http;
    private readonly AzureDevOpsOptions options;

    public AzureDevOpsClient(HttpClient http, IOptions<AzureDevOpsOptions> options)
    {
        this.http = http;
        this.options = options.Value;
        if (!this.options.Configured) return;
        http.BaseAddress = new Uri($"https://dev.azure.com/{Uri.EscapeDataString(this.options.OrganizationName)}/");
        http.Timeout = TimeSpan.FromSeconds(120);   // l'arborescence complète d'un gros dossier TFVC peut être longue
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(":" + this.options.Pat)));
    }

    public bool Configured => options.Configured;

    public async Task<List<string>> ListProjectsAsync(CancellationToken ct)
    {
        if (options.ProjectList.Length > 0) return options.ProjectList.ToList();
        using var doc = await GetJsonAsync($"_apis/projects?$top=500&{ApiVersion}", ct);
        return doc.RootElement.GetProperty("value").EnumerateArray().Select(p => p.GetProperty("name").GetString()!).Order().ToList();
    }

    public async Task<List<AzdoRepo>> ListReposAsync(string project, CancellationToken ct)
    {
        using var doc = await GetJsonAsync($"{Uri.EscapeDataString(project)}/_apis/git/repositories?{ApiVersion}", ct);
        return doc.RootElement.GetProperty("value").EnumerateArray()
            .Where(r => !(r.TryGetProperty("isDisabled", out var d) && d.ValueKind == JsonValueKind.True))
            .Select(r => new AzdoRepo(project, r.GetProperty("name").GetString()!,
                r.TryGetProperty("defaultBranch", out var b) ? b.GetString()?.Replace("refs/heads/", "") : null))
            .OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Chemins de tous les fichiers de la branche ; null si la branche n'existe pas ou si le dépôt est vide.</summary>
    public async Task<List<string>?> ListFilesAsync(string project, string repo, string branch, CancellationToken ct)
    {
        var url = $"{Uri.EscapeDataString(project)}/_apis/git/repositories/{Uri.EscapeDataString(repo)}/items" +
                  $"?recursionLevel=Full&{Version(branch)}&{ApiVersion}";
        using var res = await http.GetAsync(url, ct);
        if (res.StatusCode == HttpStatusCode.NotFound) return null;
        await EnsureOkAsync(res, ct);
        using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
        return doc.RootElement.GetProperty("value").EnumerateArray()
            .Where(i => !(i.TryGetProperty("isFolder", out var f) && f.ValueKind == JsonValueKind.True)
                        && i.TryGetProperty("gitObjectType", out var t) && t.GetString() == "blob")
            .Select(i => i.GetProperty("path").GetString()!).ToList();
    }

    public async Task<string?> GetFileAsync(string project, string repo, string branch, string path, CancellationToken ct)
    {
        var url = $"{Uri.EscapeDataString(project)}/_apis/git/repositories/{Uri.EscapeDataString(repo)}/items" +
                  $"?path={Uri.EscapeDataString(path)}&{Version(branch)}&$format=text&download=true&{ApiVersion}";
        using var res = await http.GetAsync(url, ct);
        if (res.StatusCode == HttpStatusCode.NotFound) return null;
        await EnsureOkAsync(res, ct);
        return (await res.Content.ReadAsStringAsync(ct)).TrimStart('﻿');
    }

    /// <summary>"Git" ou "Tfvc" selon le contrôle de version du projet (Git par défaut si indéterminé).</summary>
    public async Task<string> GetSourceControlTypeAsync(string project, CancellationToken ct)
    {
        try
        {
            using var doc = await GetJsonAsync($"_apis/projects/{Uri.EscapeDataString(project)}?includeCapabilities=true&{ApiVersion}", ct);
            return doc.RootElement.GetProperty("capabilities").GetProperty("versioncontrol").GetProperty("sourceControlType").GetString() ?? "Git";
        }
        catch (Exception ex) when (ex is KeyNotFoundException or InvalidOperationException) { return "Git"; }
    }

    /// <summary>Dossiers de premier niveau d'un projet TFVC ("$/Projet/Main"…).</summary>
    public async Task<List<string>> ListTfvcFoldersAsync(string project, CancellationToken ct)
    {
        var root = $"$/{project}";
        using var doc = await GetJsonAsync($"{Uri.EscapeDataString(project)}/_apis/tfvc/items?scopePath={Uri.EscapeDataString(root)}&recursionLevel=OneLevel&{ApiVersion}", ct);
        return doc.RootElement.GetProperty("value").EnumerateArray()
            .Where(i => i.TryGetProperty("isFolder", out var f) && f.ValueKind == JsonValueKind.True)
            .Select(i => i.GetProperty("path").GetString()!)
            .Where(p => !p.Equals(root, StringComparison.OrdinalIgnoreCase)).Order().ToList();
    }

    /// <summary>Chemins de tous les fichiers sous un dossier TFVC (dernière version) ; null si le dossier n'existe pas.</summary>
    public async Task<List<string>?> ListTfvcFilesAsync(string project, string scopePath, CancellationToken ct)
    {
        var url = $"{Uri.EscapeDataString(project)}/_apis/tfvc/items?scopePath={Uri.EscapeDataString(scopePath)}&recursionLevel=Full&{ApiVersion}";
        using var res = await http.GetAsync(url, ct);
        if (res.StatusCode == HttpStatusCode.NotFound) return null;
        await EnsureOkAsync(res, ct);
        using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
        return doc.RootElement.GetProperty("value").EnumerateArray()
            .Where(i => !(i.TryGetProperty("isFolder", out var f) && f.ValueKind == JsonValueKind.True))
            .Select(i => i.GetProperty("path").GetString()!).ToList();
    }

    public async Task<string?> GetTfvcFileAsync(string project, string path, CancellationToken ct)
    {
        var url = $"{Uri.EscapeDataString(project)}/_apis/tfvc/items?path={Uri.EscapeDataString(path)}&$format=text&download=true&{ApiVersion}";
        using var res = await http.GetAsync(url, ct);
        if (res.StatusCode == HttpStatusCode.NotFound) return null;
        await EnsureOkAsync(res, ct);
        return (await res.Content.ReadAsStringAsync(ct)).TrimStart('﻿');
    }

    private static string Version(string branch) =>
        $"versionDescriptor.version={Uri.EscapeDataString(branch)}&versionDescriptor.versionType=branch";

    private async Task<JsonDocument> GetJsonAsync(string url, CancellationToken ct)
    {
        using var res = await http.GetAsync(url, ct);
        await EnsureOkAsync(res, ct);
        return JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
    }

    private static async Task EnsureOkAsync(HttpResponseMessage res, CancellationToken ct)
    {
        // Un PAT invalide ou expiré renvoie 203 + page de connexion HTML, pas toujours 401
        if (res.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NonAuthoritativeInformation)
            throw new InvalidOperationException("Azure DevOps a refusé le jeton (PAT invalide ou expiré).");
        if (res.StatusCode == HttpStatusCode.Forbidden)
            throw new InvalidOperationException("Accès refusé par Azure DevOps : le PAT doit avoir la portée « Code (Read) » (et « Project and Team (Read) » pour lister les projets).");
        if (res.IsSuccessStatusCode) return;
        var body = await res.Content.ReadAsStringAsync(ct);
        throw new InvalidOperationException($"Azure DevOps a répondu {(int)res.StatusCode} : {(body.Length > 300 ? body[..300] : body)}");
    }
}
