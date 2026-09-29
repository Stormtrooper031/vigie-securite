namespace Vigie.Shared;

public sealed record RiskResult(string Severity, int RiskScore, string Explanation);

/// <summary>
/// Calcul de la criticité d'une alerte.
///   1. Sévérité de base = CVSS (v3.1 > v4.0 > v3.0 > v2, choisi par le scanner). Sans CVSS : MOYENNE par prudence.
///   2. Présente au catalogue CISA KEV (exploitée activement) : au moins ÉLEVÉE,
///      CRITIQUE si CVSS >= 7.
///   3. EPSS >= 0,5 (forte probabilité d'exploitation sous 30 j) : +1 niveau.
///   Score de risque 0..100 = CVSS x 7 + 20 (KEV) + EPSS x 10, x 0,8 si corrélation "probable".
/// </summary>
public static class RiskScorer
{
    public static RiskResult Compute(decimal? cvss, string? cvssSeverity, bool inKev, decimal? epss, string confidence = MatchConfidence.Confirmed)
    {
        var why = new List<string>();
        var severity = cvss is not null ? Severity.FromCvss(cvss) : Severity.Normalize(cvssSeverity);
        if (severity == Severity.Unknown)
        {
            severity = Severity.Medium;
            why.Add("CVSS non publié : MOYENNE par défaut");
        }
        else
        {
            why.Add($"CVSS {cvss?.ToString("0.0") ?? "?"} ({Severity.Label(severity)})");
        }

        if (inKev)
        {
            var target = cvss is >= 7.0m ? Severity.Critical : Severity.High;
            if (Severity.Rank(target) > Severity.Rank(severity))
            {
                severity = target;
                why.Add($"Exploitée activement (CISA KEV) : relevée à {Severity.Label(target)}");
            }
            else why.Add("Exploitée activement (CISA KEV)");
        }

        if (epss is >= 0.5m && severity != Severity.Critical)
        {
            severity = Severity.BumpOne(severity);
            why.Add($"EPSS {epss:0.00} : +1 niveau");
        }

        var baseScore = cvss is not null ? (double)cvss.Value * 7.0 : 35.0;
        var score = baseScore + (inKev ? 20 : 0) + (double)(epss ?? 0m) * 10.0;
        if (confidence == MatchConfidence.Probable)
        {
            score *= 0.8;
            why.Add("Corrélation probable (version partielle ou inconnue)");
        }

        return new RiskResult(severity, (int)Math.Clamp(Math.Round(score), 0, 100), string.Join(" ; ", why));
    }
}
