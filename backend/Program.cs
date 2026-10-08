using System.Text.Json.Serialization;
using Dapper;
using Vigie.Api.Data;
using Vigie.Api.Models;
using Vigie.Api.Services;

// Colonnes snake_case (PostgreSQL) <-> propriétés PascalCase (C#)
DefaultTypeMap.MatchNamesWithUnderscores = true;

var builder = WebApplication.CreateBuilder(args);

// ---- Configuration (appsettings.json + variables d'environnement Section__Cle) ----
builder.Services.Configure<SmtpOptions>(builder.Configuration.GetSection("Smtp"));
builder.Services.Configure<NotificationOptions>(builder.Configuration.GetSection("Notifications"));
builder.Services.Configure<SecurityOptions>(builder.Configuration.GetSection("Security"));
builder.Services.Configure<StackOptions>(builder.Configuration.GetSection("Stack"));
builder.Services.Configure<ScannerOptions>(builder.Configuration.GetSection("Scanner"));
builder.Services.Configure<AzureDevOpsOptions>(builder.Configuration.GetSection("AzureDevOps"));

// ---- Services ----
builder.Services.AddSingleton<Db>();
builder.Services.AddScoped<TechnologyService>();
builder.Services.AddScoped<CorrelationService>();
builder.Services.AddScoped<AlertService>();
builder.Services.AddScoped<NotificationService>();
builder.Services.AddScoped<VulnerabilityService>();
builder.Services.AddScoped<DashboardService>();
builder.Services.AddSingleton<EmailSender>();
builder.Services.AddHttpClient<ScannerClient>(c =>
{
    c.BaseAddress = new Uri(builder.Configuration["Scanner:BaseUrl"] ?? "http://scanner:8080");
    c.Timeout = TimeSpan.FromSeconds(10);
});
builder.Services.AddHttpClient<AzureDevOpsClient>();
builder.Services.AddScoped<AzureDevOpsStackService>();
builder.Services.AddHostedService<StackFileImporter>();
builder.Services.AddHostedService<NotificationScheduler>();

builder.Services.AddControllers()
    .AddJsonOptions(o => o.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.Never);
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();

var origins = (builder.Configuration["Cors:Origins"] ?? "http://localhost:3000")
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.WithOrigins(origins).AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();

// Colonnes ajoutées après la création de la base (avant tout service qui lit les tables)
await app.Services.GetRequiredService<Db>().UpgradeSchemaAsync(CancellationToken.None);

app.UseExceptionHandler();
app.UseCors();
app.MapOpenApi();           // /openapi/v1.json
app.MapControllers();
app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "vigie-backend", time = DateTime.UtcNow }));

app.Run();
