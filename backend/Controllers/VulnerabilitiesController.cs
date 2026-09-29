using System.Text;
using Microsoft.AspNetCore.Mvc;
using Vigie.Api.Models;
using Vigie.Api.Services;

namespace Vigie.Api.Controllers;

/// <summary>Vulnérabilités corrélées à ma stack.</summary>
[ApiController]
[Route("api/vulnerabilities")]
public class VulnerabilitiesController(VulnerabilityService service) : ControllerBase
{
    /// <summary>
    /// Filtres : severity=CRITICAL,HIGH · technologyId · solution · from/to (date de publication) · seenSince ·
    /// kev=true · search · sort=risk|published|cvss|seen · page · pageSize
    /// </summary>
    [HttpGet]
    public async Task<PagedResult<Vulnerability>> List([FromQuery] VulnerabilityQuery query) => await service.QueryAsync(query);

    /// <summary>Nouvelles vulnérabilités détectées par la vigie depuis N jours (défaut 7).</summary>
    [HttpGet("new")]
    public async Task<PagedResult<Vulnerability>> New([FromQuery] int days = 7, [FromQuery] string? severity = null,
        [FromQuery] int? technologyId = null, [FromQuery] string? solution = null, [FromQuery] int page = 1, [FromQuery] int pageSize = 100) =>
        await service.QueryAsync(new VulnerabilityQuery
        {
            SeenSince = DateTime.UtcNow.AddDays(-Math.Clamp(days, 1, 365)),
            Severity = severity, TechnologyId = technologyId, Solution = solution, Sort = "seen", Page = page, PageSize = pageSize
        });

    [HttpGet("{id:int}")]
    public async Task<ActionResult<VulnerabilityDetail>> Get(int id) =>
        await service.GetAsync(id) is { } d ? d : NotFound();

    /// <summary>
    /// Vide les vulnérabilités, corrélations et alertes (donc « Mises à jour à faire » aussi), et remet les
    /// technologies à « jamais scannée ». Ne touche pas à la stack ni à l'historique des courriels. Irréversible.
    /// </summary>
    [HttpPost("reset")]
    public async Task<VulnerabilityResetResult> Reset() => await service.ResetAsync();

    /// <summary>Export CSV (séparateur ;) avec les mêmes filtres que la liste.</summary>
    [HttpGet("export")]
    public async Task<FileContentResult> Export([FromQuery] VulnerabilityQuery query)
    {
        var csv = await service.ExportCsvAsync(query);
        var bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(csv)).ToArray();
        return File(bytes, "text/csv; charset=utf-8", $"vulnerabilites-{DateTime.Now:yyyyMMdd-HHmm}.csv");
    }
}
