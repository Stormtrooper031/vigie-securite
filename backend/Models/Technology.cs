using Vigie.Shared;

namespace Vigie.Api.Models;

/// <summary>Élément de ma stack à surveiller (table technologies).</summary>
public class Technology : ITechnologyTarget
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Type { get; set; } = TechTypes.Other;
    public string Vendor { get; set; } = "";
    public string Product { get; set; } = "";
    public string Version { get; set; } = "";
    public string Ecosystem { get; set; } = "";
    public string? PackageName { get; set; }
    public string? Cpe { get; set; }
    public string? Keywords { get; set; }
    public string? SourceLine { get; set; }
    public bool IsActive { get; set; } = true;
    public string? Notes { get; set; }
    /// <summary>Solutions (applications) qui utilisent la technologie ; une technologie partagée apparaît dans chaque groupe.</summary>
    public string[] Solutions { get; set; } = [];
    public DateTime? LastScannedAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    // Calculés (requêtes de liste)
    public int VulnerabilityCount { get; set; }
    public int OpenAlertCount { get; set; }
    public string? MaxSeverity { get; set; }
}

/// <summary>Saisie via formulaire (création / modification).</summary>
public class TechnologyInput
{
    public string Name { get; set; } = "";
    public string? Type { get; set; }
    public string? Vendor { get; set; }
    public string? Product { get; set; }
    public string? Version { get; set; }
    public string? Ecosystem { get; set; }
    public string? PackageName { get; set; }
    public string? Cpe { get; set; }
    public string? Keywords { get; set; }
    public string? Notes { get; set; }
    public string[]? Solutions { get; set; }
    public bool IsActive { get; set; } = true;
}

/// <summary>Import en lot : texte au format de config/stack.txt.</summary>
public class TechnologyImportRequest
{
    public string Text { get; set; } = "";
    /// <summary>true = simulation (renvoie la normalisation sans rien enregistrer).</summary>
    public bool DryRun { get; set; }
}

public class TechnologyImportResult
{
    public int Created { get; set; }
    public int Updated { get; set; }
    public int Unchanged { get; set; }
    public List<TechnologyImportLine> Lines { get; set; } = [];
}

public class TechnologyImportLine
{
    public int Line { get; set; }
    public string? Source { get; set; }
    public string? Status { get; set; }   // created|updated|unchanged|error|preview
    public string? Error { get; set; }
    public NormalizedTechnology? Normalized { get; set; }
    public int? TechnologyId { get; set; }
}

/// <summary>"Mise à jour à faire" : version minimale qui corrige toutes les failles ouvertes connues.</summary>
public class TechnologyUpdate
{
    public int TechnologyId { get; set; }
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public string CurrentVersion { get; set; } = "";
    public string? RecommendedVersion { get; set; }
    public string MaxSeverity { get; set; } = "";
    public int OpenAlerts { get; set; }
    public int Critical { get; set; }
    public int High { get; set; }
    public int Kev { get; set; }
    public int WithoutFix { get; set; }
    public List<string> TopCves { get; set; } = [];
}
