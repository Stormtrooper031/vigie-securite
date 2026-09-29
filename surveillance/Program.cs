// =====================================================================
//  Vigie Sécurité - service de surveillance (scanner)
//  Collecte NVD / CISA KEV / MITRE / OSV / EPSS, corrélation avec la stack,
//  enregistrement dans PostgreSQL et déclenchement des alertes via le backend.
// =====================================================================
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Microsoft.Extensions.Options;
using Vigie.Scanner;
using Vigie.Scanner.Services;
using Vigie.Scanner.Sources;

DefaultTypeMap.MatchNamesWithUnderscores = true;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<ScanOptions>(builder.Configuration.GetSection("Scan"));
builder.Services.Configure<SourcesOptions>(builder.Configuration.GetSection("Sources"));
builder.Services.Configure<BackendOptions>(builder.Configuration.GetSection("Backend"));
builder.Services.Configure<SecurityOptions>(builder.Configuration.GetSection("Security"));

const string UserAgent = "VigieSecurite/1.0 (+surveillance locale)";
void Http(HttpClient c, int timeoutSeconds)
{
    c.Timeout = TimeSpan.FromSeconds(timeoutSeconds);
    c.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
}

// Sources (le proxy d'entreprise est pris en compte via HTTPS_PROXY / NO_PROXY)
builder.Services.AddHttpClient<NvdSource>(c => Http(c, 180));
builder.Services.AddHttpClient<OsvSource>(c => Http(c, 60));
builder.Services.AddHttpClient<MitreSource>(c => Http(c, 30));
builder.Services.AddHttpClient<CisaKevSource>(c => Http(c, 120));
builder.Services.AddHttpClient<EpssSource>(c => Http(c, 60));
builder.Services.AddHttpClient<BackendClient>(c =>
{
    Http(c, 120);
    c.BaseAddress = new Uri(builder.Configuration["Backend:BaseUrl"] ?? "http://backend:8080");
});

// Sources interrogées par technologie (ordre = priorité de fusion)
builder.Services.AddTransient<ITechnologySource>(sp => sp.GetRequiredService<NvdSource>());
builder.Services.AddTransient<ITechnologySource>(sp => sp.GetRequiredService<OsvSource>());

builder.Services.AddSingleton<ScanRepository>();
builder.Services.AddSingleton<ScanStatus>();
builder.Services.AddScoped<ScanOrchestrator>();
builder.Services.AddSingleton<ScanWorker>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ScanWorker>());

var app = builder.Build();

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "vigie-scanner" }));

app.MapGet("/status", (ScanStatus s, IOptionsMonitor<ScanOptions> o, IOptionsMonitor<SourcesOptions> src) => Results.Ok(new
{
    s.Running, s.CurrentTrigger, s.CurrentStep, s.StartedAt, s.LastRunId, s.LastStatus, s.LastFinishedAt, s.NextScheduledAt, s.Queued,
    schedule = string.IsNullOrWhiteSpace(o.CurrentValue.DailyAt) ? $"toutes les {o.CurrentValue.IntervalMinutes} min" : $"chaque jour à {o.CurrentValue.DailyAt}",
    sources = new
    {
        nvd = src.CurrentValue.Nvd.Enabled, nvdApiKey = !string.IsNullOrWhiteSpace(src.CurrentValue.Nvd.ApiKey),
        kev = src.CurrentValue.Kev.Enabled, mitre = src.CurrentValue.Mitre.Enabled,
        osv = src.CurrentValue.Osv.Enabled, epss = src.CurrentValue.Epss.Enabled
    }
}));

app.MapPost("/scan", (HttpRequest req, int? technologyId, ScanWorker worker, IOptions<SecurityOptions> sec) =>
{
    var expected = sec.Value.InternalApiKey;
    var provided = req.Headers["X-Api-Key"].ToString();
    if (string.IsNullOrEmpty(expected) ||
        !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(provided)))
        return Results.Unauthorized();

    return worker.Enqueue(new ScanRequest("manual", technologyId))
        ? Results.Accepted(value: new { message = "Scan ajouté à la file." })
        : Results.Conflict(new { error = "File de scans pleine." });
});

app.Run();
