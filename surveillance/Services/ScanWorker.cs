using System.Threading.Channels;
using Microsoft.Extensions.Options;

namespace Vigie.Scanner.Services;

/// <summary>
/// Planification des scans :
///   - au démarrage (Scan:OnStartup, après Scan:StartupDelaySeconds) ;
///   - puis toutes les Scan:IntervalMinutes minutes, OU chaque jour à Scan:DailyAt (HH:mm, heure locale TZ) ;
///   - à la demande via POST /scan (bouton "Lancer un scan" du tableau de bord).
/// Les demandes passent par une file : un seul scan à la fois.
/// </summary>
public sealed class ScanWorker(IServiceScopeFactory scopes, ScanRepository repo, ScanStatus status,
    IOptionsMonitor<ScanOptions> options, ILogger<ScanWorker> logger) : BackgroundService
{
    private readonly Channel<ScanRequest> _queue = Channel.CreateBounded<ScanRequest>(new BoundedChannelOptions(20) { FullMode = BoundedChannelFullMode.DropWrite });
    private readonly HashSet<ScanRequest> _pending = [];
    private readonly Lock _lock = new();

    public bool Enqueue(ScanRequest request)
    {
        lock (_lock)
        {
            // Évite d'empiler deux fois la même demande
            if (_pending.Any(p => p.TechnologyId == request.TechnologyId)) return true;
            if (!_queue.Writer.TryWrite(request)) return false;
            _pending.Add(request);
            status.Queued = _pending.Count;
            return true;
        }
    }

    public static DateTime NextRun(ScanOptions o, DateTime nowLocal)
    {
        if (!string.IsNullOrWhiteSpace(o.DailyAt) && TimeOnly.TryParse(o.DailyAt, out var at))
        {
            var t = nowLocal.Date.Add(at.ToTimeSpan());
            return t > nowLocal ? t : t.AddDays(1);
        }
        return nowLocal.AddMinutes(Math.Max(15, o.IntervalMinutes));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await repo.WaitUntilReadyAsync(logger, stoppingToken);
        await repo.CloseOrphanRunsAsync();

        _ = Task.Run(() => ScheduleLoopAsync(stoppingToken), stoppingToken);

        await foreach (var request in _queue.Reader.ReadAllAsync(stoppingToken))
        {
            lock (_lock) { _pending.Remove(request); status.Queued = _pending.Count; }
            try
            {
                using var scope = scopes.CreateScope();
                await scope.ServiceProvider.GetRequiredService<ScanOrchestrator>().RunAsync(request, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Scan en échec");
            }
        }
    }

    private async Task ScheduleLoopAsync(CancellationToken ct)
    {
        var o = options.CurrentValue;
        if (o.OnStartup)
        {
            await Task.Delay(TimeSpan.FromSeconds(Math.Max(0, o.StartupDelaySeconds)), ct);
            Enqueue(new ScanRequest("startup", null));
        }

        while (!ct.IsCancellationRequested)
        {
            var next = NextRun(options.CurrentValue, DateTime.Now);
            status.NextScheduledAt = next.ToUniversalTime();
            logger.LogInformation("Prochain scan planifié : {Next:yyyy-MM-dd HH:mm}", next);
            var delay = next - DateTime.Now;
            if (delay > TimeSpan.Zero) await Task.Delay(delay, ct);
            Enqueue(new ScanRequest("schedule", null));
        }
    }
}
