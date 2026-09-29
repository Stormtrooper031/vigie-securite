using Vigie.Scanner.Models;

namespace Vigie.Scanner.Sources;

/// <summary>
/// Source interrogée pour chaque technologie. Pour ajouter une source (bulletin d'un fournisseur,
/// flux interne...) : implémenter cette interface, convertir vers NormalizedVulnerability
/// (avec des AffectedRule pour la corrélation), puis l'enregistrer dans Program.cs.
/// </summary>
public interface ITechnologySource
{
    string Name { get; }
    bool Enabled { get; }

    /// <param name="since">null = inventaire complet ; sinon failles modifiées depuis cette date (UTC).</param>
    Task<IReadOnlyList<NormalizedVulnerability>> FetchAsync(ScanTechnology tech, DateTime? since, ScanLog log, CancellationToken ct);
}
