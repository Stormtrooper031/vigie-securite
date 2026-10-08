using Microsoft.AspNetCore.Mvc;
using Vigie.Api.Models;
using Vigie.Api.Services;

namespace Vigie.Api.Controllers;

/// <summary>Déduit la stack des solutions à partir des dépôts Azure DevOps (lecture seule).</summary>
[ApiController]
[Route("api/azure-devops")]
public class AzureDevOpsController(AzureDevOpsStackService service) : ControllerBase
{
    /// <summary>Dépôts accessibles avec le PAT configuré.</summary>
    [HttpGet("repositories")]
    public async Task<ActionResult<List<AzdoRepoInfo>>> Repositories(CancellationToken ct)
    {
        if (!service.Configured) return BadRequest(new { error = "Azure DevOps n'est pas configuré (AZDO_ORGANIZATION et AZDO_PAT dans .env)." });
        try { return await service.ListRepositoriesAsync(ct); }
        catch (InvalidOperationException ex) { return BadRequest(new { error = ex.Message }); }
        catch (HttpRequestException) { return StatusCode(502, new { error = "Azure DevOps est injoignable." }); }
    }

    /// <summary>Analyse les dépôts choisis et renvoie la stack au format config/stack.txt (rien n'est enregistré).</summary>
    [HttpPost("scan")]
    public async Task<ActionResult<AzdoScanResult>> Scan(AzdoScanRequest request, CancellationToken ct)
    {
        if (!service.Configured) return BadRequest(new { error = "Azure DevOps n'est pas configuré (AZDO_ORGANIZATION et AZDO_PAT dans .env)." });
        if (request.Targets.Count == 0) return BadRequest(new { error = "Aucun dépôt sélectionné." });
        return await service.ScanAsync(request.Targets, ct);
    }
}
