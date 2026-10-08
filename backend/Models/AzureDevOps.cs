namespace Vigie.Api.Models;

public class AzureDevOpsOptions
{
    /// <summary>Nom de l'organisation ("monorg") ou URL complète (https://dev.azure.com/monorg).</summary>
    public string Organization { get; set; } = "";
    /// <summary>Projets à lire, séparés par des virgules. Vide = tous les projets accessibles au PAT.</summary>
    public string Projects { get; set; } = "";
    /// <summary>Personal Access Token, portée « Code (Read) » (et « Project and Team (Read) » si Projects est vide).</summary>
    public string Pat { get; set; } = "";

    public bool Configured => OrganizationName.Length > 0 && !string.IsNullOrWhiteSpace(Pat);

    public string OrganizationName
    {
        get
        {
            // Accepte "monorg", "https://dev.azure.com/monorg" et l'ancienne forme "https://monorg.visualstudio.com"
            var o = Organization.Trim().TrimEnd('/');
            if (o.Contains("://")) o = o[(o.IndexOf("://", StringComparison.Ordinal) + 3)..];
            var host = o.Split('/')[0];
            if (host.EndsWith(".visualstudio.com", StringComparison.OrdinalIgnoreCase)) return host[..host.IndexOf('.')];
            var i = o.IndexOf('/');
            return i >= 0 ? o[(i + 1)..].Split('/')[0] : o;
        }
    }

    /// <summary>Noms décodés : un nom copié depuis une URL ("Accès%20HVS") est accepté.</summary>
    public string[] ProjectList => Projects.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(Uri.UnescapeDataString).ToArray();
}

public record AzdoRepo(string Project, string Name, string? DefaultBranch);

/// <summary>Dépôt proposé à l'utilisateur ; la solution suggérée est le nom du dépôt.</summary>
public class AzdoRepoInfo
{
    public string Project { get; set; } = "";
    public string Name { get; set; } = "";
    public string? DefaultBranch { get; set; }
    public string SuggestedSolution { get; set; } = "";
    /// <summary>"git" ou "tfvc" (Name est alors un chemin "$/Projet/Dossier").</summary>
    public string Kind { get; set; } = "git";
}

/// <summary>Dépôt à analyser et solution à laquelle rattacher sa stack (plusieurs dépôts peuvent partager une solution).</summary>
public class AzdoScanTarget
{
    public string Project { get; set; } = "";
    public string Repo { get; set; } = "";
    public string Solution { get; set; } = "";
    /// <summary>Vide = branche par défaut du dépôt, sinon main puis master.</summary>
    public string? Branch { get; set; }
    /// <summary>"git" (défaut) ou "tfvc" : Repo est alors le dossier TFVC à lire ("$/Projet/Dossier").</summary>
    public string Kind { get; set; } = "git";
}

public class AzdoScanRequest
{
    public List<AzdoScanTarget> Targets { get; set; } = [];
}

public class AzdoRepoResult
{
    public string Project { get; set; } = "";
    public string Repo { get; set; } = "";
    public string Solution { get; set; } = "";
    public string? Branch { get; set; }
    public List<string> Files { get; set; } = [];
    public int Technologies { get; set; }
    public List<string> Warnings { get; set; } = [];
    public string? Error { get; set; }
}

public class AzdoScanResult
{
    /// <summary>Stack au format config/stack.txt (sections [Solution]), prête pour l'aperçu et l'import.</summary>
    public string Text { get; set; } = "";
    public List<AzdoRepoResult> Repos { get; set; } = [];
}
