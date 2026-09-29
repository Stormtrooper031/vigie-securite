using Microsoft.Extensions.Options;
using Vigie.Api.Models;

namespace Vigie.Api.Services;

/// <summary>
/// Planificateur des courriels de résumé selon NOTIFY_FREQUENCY :
///   immediate : vérification chaque minute
///   hourly    : chaque heure pile
///   daily     : chaque jour à NOTIFY_DAILY_AT (heure locale, variable TZ)
///   weekly    : chaque NOTIFY_WEEKLY_DAY à NOTIFY_DAILY_AT
/// </summary>
public sealed class NotificationScheduler(IServiceScopeFactory scopes, IOptionsMonitor<NotificationOptions> options, ILogger<NotificationScheduler> logger)
    : BackgroundService
{
    public static DateTime? NextRun(NotificationOptions o, DateTime nowLocal)
    {
        if (!o.Enabled) return null;
        var freq = o.Frequency.ToLowerInvariant();
        if (freq == "immediate") return nowLocal.AddMinutes(1);
        if (freq == "hourly") return new DateTime(nowLocal.Year, nowLocal.Month, nowLocal.Day, nowLocal.Hour, 0, 0).AddHours(1);

        var at = TimeOnly.TryParse(o.DailyAt, out var t) ? t : new TimeOnly(7, 30);
        var candidate = nowLocal.Date.Add(at.ToTimeSpan());
        if (freq == "weekly")
        {
            var day = Enum.TryParse<DayOfWeek>(o.WeeklyDay, true, out var d) ? d : DayOfWeek.Monday;
            while (candidate.DayOfWeek != day || candidate <= nowLocal) candidate = candidate.AddDays(1);
            return candidate;
        }
        return candidate > nowLocal ? candidate : candidate.AddDays(1);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(20), stoppingToken);
        var next = NextRun(options.CurrentValue, DateTime.Now);
        logger.LogInformation("Planificateur de courriels : fréquence {Freq}, prochain envoi {Next}", options.CurrentValue.Frequency, next);

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            var o = options.CurrentValue;
            next ??= NextRun(o, DateTime.Now);
            if (next is null || DateTime.Now < next) continue;

            try
            {
                using var scope = scopes.CreateScope();
                var svc = scope.ServiceProvider.GetRequiredService<NotificationService>();
                var isImmediate = o.Frequency.Equals("immediate", StringComparison.OrdinalIgnoreCase);
                var n = await svc.SendPendingAsync(isImmediate ? "immediate" : "digest", o.MinSeverity, includeBaselineSummary: true, stoppingToken);
                if (n is not null) logger.LogInformation("Résumé envoyé : notification {Id} ({Count} alertes, {Status})", n.Id, n.AlertCount, n.Status);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Erreur du planificateur de courriels");
            }
            next = NextRun(o, DateTime.Now);
        }
    }
}
