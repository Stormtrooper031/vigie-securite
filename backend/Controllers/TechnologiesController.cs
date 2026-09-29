using System.Text;
using Microsoft.AspNetCore.Mvc;
using Vigie.Api.Models;
using Vigie.Api.Services;
using Vigie.Shared;

namespace Vigie.Api.Controllers;

/// <summary>Ma stack technologique.</summary>
[ApiController]
[Route("api/technologies")]
public class TechnologiesController(TechnologyService service, CorrelationService correlation) : ControllerBase
{
    /// <summary>Liste des technologies avec nombre de failles et d'alertes ouvertes.</summary>
    [HttpGet]
    public async Task<List<Technology>> List([FromQuery] bool? active) => await service.ListAsync(active);

    /// <summary>Mises à jour à faire : version minimale corrigeant les failles ouvertes, par technologie.</summary>
    [HttpGet("updates")]
    public async Task<List<TechnologyUpdate>> Updates() => await service.GetUpdatesAsync();

    /// <summary>Export au format config/stack.txt (réimportable).</summary>
    [HttpGet("export")]
    public async Task<FileContentResult> Export()
    {
        var text = await service.ExportAsync();
        var bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(text)).ToArray();
        return File(bytes, "text/plain; charset=utf-8", $"stack-{DateTime.Now:yyyyMMdd-HHmm}.txt");
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<Technology>> Get(int id) =>
        await service.GetAsync(id) is { } t ? t : NotFound();

    /// <summary>Types et écosystèmes acceptés (listes déroulantes du formulaire).</summary>
    [HttpGet("meta")]
    public object Meta() => new
    {
        types = TechTypes.All,
        ecosystems = new[] { "npm", "NuGet", "PyPI", "Packagist", "Maven", "Go", "crates.io", "RubyGems", "Debian", "Ubuntu", "Alpine" }
    };

    /// <summary>Aperçu de la normalisation d'une ligne ("npm:react@18.2.0").</summary>
    [HttpGet("normalize")]
    public ActionResult<NormalizedTechnology> Normalize([FromQuery] string line)
    {
        try { return TechnologyNormalizer.ParseLine(line); }
        catch (FormatException ex) { return BadRequest(new { error = ex.Message }); }
    }

    [HttpPost]
    public async Task<ActionResult<Technology>> Create(TechnologyInput input)
    {
        try
        {
            var t = await service.CreateAsync(input);
            return CreatedAtAction(nameof(Get), new { id = t.Id }, t);
        }
        catch (ArgumentException ex) { return BadRequest(new { error = ex.Message }); }
        catch (InvalidOperationException ex) { return Conflict(new { error = ex.Message }); }
        catch (FormatException ex) { return BadRequest(new { error = ex.Message }); }
    }

    [HttpPut("{id:int}")]
    public async Task<ActionResult<Technology>> Update(int id, TechnologyInput input)
    {
        try { return await service.UpdateAsync(id, input) is { } t ? t : NotFound(); }
        catch (FormatException ex) { return BadRequest(new { error = ex.Message }); }
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id) => await service.DeleteAsync(id) ? NoContent() : NotFound();

    /// <summary>Import en lot (format config/stack.txt). dryRun=true pour prévisualiser.</summary>
    [HttpPost("import")]
    public async Task<TechnologyImportResult> Import(TechnologyImportRequest request) =>
        await service.ImportAsync(request.Text, request.DryRun);

    /// <summary>Recalcule la corrélation avec les failles déjà en base.</summary>
    [HttpPost("{id:int}/recorrelate")]
    public async Task<ActionResult<CorrelationSummary>> Recorrelate(int id)
    {
        var t = await service.GetAsync(id);
        if (t is null) return NotFound();
        return await correlation.RecorrelateTechnologyAsync(t, baseline: false);
    }

    /// <summary>Force un inventaire complet de cette technologie au prochain passage du scanner (déclenché tout de suite).</summary>
    [HttpPost("{id:int}/rescan")]
    public async Task<IActionResult> Rescan(int id) =>
        await service.RequestRescanAsync(id) ? Accepted() : NotFound();
}
