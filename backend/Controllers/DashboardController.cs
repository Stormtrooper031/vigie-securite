using Dapper;
using Microsoft.AspNetCore.Mvc;
using Vigie.Api.Data;
using Vigie.Api.Models;
using Vigie.Api.Services;

namespace Vigie.Api.Controllers;

[ApiController]
[Route("api")]
public class DashboardController(DashboardService dashboard, NotificationService notifications, ScannerClient scanner, Db db) : ControllerBase
{
    /// <summary>Indicateurs globaux + graphiques.</summary>
    [HttpGet("dashboard")]
    public async Task<DashboardStats> Get([FromQuery] int days = 30) => await dashboard.GetAsync(Math.Clamp(days, 7, 365));

    // ---------------- Notifications ----------------

    [HttpGet("notifications")]
    public async Task<List<Notification>> Notifications() => await notifications.ListAsync();

    [HttpGet("notifications/{id:int}")]
    public async Task<ActionResult<Notification>> Notification(int id) =>
        await notifications.GetAsync(id) is { } n ? n : NotFound();

    /// <summary>Envoie un courriel de test (to optionnel, sinon NOTIFY_TO).</summary>
    [HttpPost("notifications/test")]
    public async Task<Notification> Test([FromQuery] string? to) => await notifications.SendTestAsync(to);

    /// <summary>Envoie tout de suite le résumé des alertes en attente (seuil minSeverity optionnel).</summary>
    [HttpPost("notifications/send-now")]
    public async Task<ActionResult<Notification>> SendNow([FromQuery] string? minSeverity,
        [FromServices] Microsoft.Extensions.Options.IOptionsMonitor<NotificationOptions> opts)
    {
        var n = await notifications.SendPendingAsync("digest", minSeverity ?? opts.CurrentValue.MinSeverity, includeBaselineSummary: true);
        return n is null ? Ok(new { message = "Aucune alerte en attente d'envoi." }) : n;
    }

    // ---------------- Scans ----------------

    [HttpGet("scans")]
    public async Task<IEnumerable<ScanRun>> Scans([FromQuery] int limit = 50)
    {
        await using var cn = await db.OpenAsync();
        return await cn.QueryAsync<ScanRun>("SELECT * FROM scan_runs ORDER BY id DESC LIMIT @limit", new { limit = Math.Clamp(limit, 1, 500) });
    }

    /// <summary>Lance un scan maintenant (toutes les technologies, ou une seule).</summary>
    [HttpPost("scans/trigger")]
    public async Task<IActionResult> Trigger([FromQuery] int? technologyId) =>
        await scanner.TriggerAsync(technologyId)
            ? Accepted(new { message = "Scan demandé." })
            : StatusCode(503, new { error = "Service de surveillance injoignable ou scan déjà en cours." });

    [HttpGet("scans/status")]
    public async Task<IActionResult> ScannerStatus() =>
        await scanner.StatusAsync() is { } s ? Ok(s) : StatusCode(503, new { error = "Service de surveillance injoignable." });
}
