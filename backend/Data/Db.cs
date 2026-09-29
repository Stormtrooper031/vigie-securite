using Npgsql;

namespace Vigie.Api.Data;

/// <summary>Accès PostgreSQL (Npgsql + Dapper). Une seule source de données (pool) pour l'application.</summary>
public sealed class Db(IConfiguration config, ILogger<Db> logger) : IAsyncDisposable
{
    private readonly NpgsqlDataSource _dataSource = NpgsqlDataSource.Create(
        config.GetConnectionString("Vigie") ?? throw new InvalidOperationException("ConnectionStrings:Vigie manquant"));

    public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct = default) =>
        await _dataSource.OpenConnectionAsync(ct);

    /// <summary>Attend que PostgreSQL accepte les connexions (démarrage du conteneur).</summary>
    public async Task WaitUntilReadyAsync(CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await using var cn = await OpenAsync(ct);
                return;
            }
            catch (NpgsqlException ex) when (attempt < 30)
            {
                logger.LogWarning("PostgreSQL indisponible (tentative {Attempt}/30) : {Message}", attempt, ex.Message);
                await Task.Delay(TimeSpan.FromSeconds(3), ct);
            }
        }
    }

    /// <summary>
    /// Mises à niveau du schéma pour les bases créées avant une évolution (init.sql ne s'exécute
    /// qu'à la création du volume). Chaque instruction doit être idempotente.
    /// </summary>
    private static readonly string[] SchemaUpgrades =
    [
        "ALTER TABLE technologies ADD COLUMN IF NOT EXISTS solutions text[] NOT NULL DEFAULT '{}'",
    ];

    public async Task UpgradeSchemaAsync(CancellationToken ct)
    {
        await WaitUntilReadyAsync(ct);
        await using var cn = await OpenAsync(ct);
        foreach (var sql in SchemaUpgrades)
        {
            await using var cmd = new NpgsqlCommand(sql, cn);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    public ValueTask DisposeAsync() => _dataSource.DisposeAsync();
}
