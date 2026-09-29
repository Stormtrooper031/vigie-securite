using Microsoft.AspNetCore.Mvc;
using Vigie.Api.Models;
using Vigie.Api.Services;

namespace Vigie.Api.Controllers;

/// <summary>Alertes (faille pertinente pour une technologie) et leur suivi.</summary>
[ApiController]
[Route("api/alerts")]
public class AlertsController(AlertService service) : ControllerBase
{
    /// <summary>Filtres : status=new,acknowledged · severity=CRITICAL,HIGH · technologyId · includeBaseline</summary>
    [HttpGet]
    public async Task<PagedResult<Alert>> List([FromQuery] AlertQuery query) => await service.QueryAsync(query);

    /// <summary>Changer le statut : new | acknowledged | resolved | ignored</summary>
    [HttpPatch("{id:int}/status")]
    public async Task<IActionResult> UpdateStatus(int id, AlertStatusUpdate body)
    {
        try { return await service.UpdateStatusAsync([id], body.Status, body.Comment) > 0 ? NoContent() : NotFound(); }
        catch (ArgumentException ex) { return BadRequest(new { error = ex.Message }); }
    }

    [HttpPatch("status")]
    public async Task<IActionResult> UpdateStatusBulk(AlertBulkStatusUpdate body)
    {
        try { return Ok(new { updated = await service.UpdateStatusAsync(body.Ids, body.Status, body.Comment) }); }
        catch (ArgumentException ex) { return BadRequest(new { error = ex.Message }); }
    }

    /// <summary>Route interne appelée par le service de surveillance (en-tête X-Api-Key).</summary>
    [HttpPost("ingest")]
    [InternalApiKey]
    public async Task<AlertIngestResult> Ingest(AlertIngestRequest request) => await service.IngestAsync(request);
}
