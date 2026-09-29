namespace Vigie.Scanner.Sources;

/// <summary>
/// Calcul du score de base CVSS v3.x à partir du vecteur (OSV ne fournit que le vecteur).
/// Spécification FIRST CVSS v3.1, section 7.
/// </summary>
public static class CvssCalculator
{
    public static decimal? BaseScoreV3(string? vector)
    {
        if (string.IsNullOrWhiteSpace(vector) || !vector.StartsWith("CVSS:3", StringComparison.OrdinalIgnoreCase)) return null;
        var m = vector.Split('/').Skip(1).Select(p => p.Split(':')).Where(p => p.Length == 2)
            .ToDictionary(p => p[0].ToUpperInvariant(), p => p[1].ToUpperInvariant());
        try
        {
            var scopeChanged = m["S"] == "C";
            var av = m["AV"] switch { "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2, _ => throw new FormatException() };
            var ac = m["AC"] switch { "L" => 0.77, "H" => 0.44, _ => throw new FormatException() };
            var pr = m["PR"] switch
            {
                "N" => 0.85,
                "L" => scopeChanged ? 0.68 : 0.62,
                "H" => scopeChanged ? 0.5 : 0.27,
                _ => throw new FormatException()
            };
            var ui = m["UI"] switch { "N" => 0.85, "R" => 0.62, _ => throw new FormatException() };
            double Cia(string k) => m[k] switch { "H" => 0.56, "L" => 0.22, "N" => 0, _ => throw new FormatException() };

            var iss = 1 - (1 - Cia("C")) * (1 - Cia("I")) * (1 - Cia("A"));
            var impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.Pow(iss - 0.02, 15) : 6.42 * iss;
            var exploitability = 8.22 * av * ac * pr * ui;
            if (impact <= 0) return 0m;
            var score = scopeChanged ? Roundup(Math.Min(1.08 * (impact + exploitability), 10)) : Roundup(Math.Min(impact + exploitability, 10));
            return (decimal)score;
        }
        catch (Exception e) when (e is KeyNotFoundException or FormatException)
        {
            return null;
        }
    }

    private static double Roundup(double x)
    {
        var i = (long)Math.Round(x * 100000);
        return i % 10000 == 0 ? i / 100000.0 : (Math.Floor(i / 10000.0) + 1) / 10.0;
    }
}
