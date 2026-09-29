using Microsoft.Extensions.Options;
using Vigie.Api.Data;
using Vigie.Api.Models;

namespace Vigie.Api.Services;

/// <summary>Au démarrage : attend PostgreSQL puis importe config/stack.txt (ajouts et mises à jour seulement).</summary>
public sealed class StackFileImporter(IServiceScopeFactory scopes, Db db, IOptions<StackOptions> options, ILogger<StackFileImporter> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await db.WaitUntilReadyAsync(stoppingToken);
        var o = options.Value;
        if (!o.ImportOnStartup) return;
        if (!File.Exists(o.File))
        {
            logger.LogInformation("Aucun fichier de stack à importer ({File})", o.File);
            return;
        }

        try
        {
            var text = await File.ReadAllTextAsync(o.File, stoppingToken);
            using var scope = scopes.CreateScope();
            var svc = scope.ServiceProvider.GetRequiredService<TechnologyService>();
            // Pas de déclenchement : le scanner fait son propre scan au démarrage
            var r = await svc.ImportAsync(text, dryRun: false, triggerScan: false);
            logger.LogInformation("Import de {File} : {Created} créées, {Updated} mises à jour, {Unchanged} inchangées, {Errors} erreurs",
                o.File, r.Created, r.Updated, r.Unchanged, r.Lines.Count(l => l.Status == "error"));
            foreach (var err in r.Lines.Where(l => l.Status == "error"))
                logger.LogWarning("stack.txt ligne {Line} : {Error}", err.Line, err.Error);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Import de la stack impossible");
        }
    }
}
