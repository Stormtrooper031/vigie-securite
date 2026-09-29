using System.Text.RegularExpressions;

namespace Vigie.Shared;

/// <summary>
/// Comparaison tolérante de versions (semver, x.y.z.w, suffixes rc/beta, epoch Debian "1:").
/// Suffisante pour décider si une version installée tombe dans une plage publiée.
/// </summary>
public static partial class VersionComparer
{
    [GeneratedRegex(@"\d+|[a-zA-Z]+")]
    private static partial Regex TokenRegex();

    /// <summary>Retire les préfixes/suffixes non comparables : "v1.2", "1:2.3", "1.2+build".</summary>
    public static string Clean(string? version)
    {
        var v = (version ?? "").Trim();
        if (v.Length > 0 && (v[0] == 'v' || v[0] == 'V') && v.Length > 1 && char.IsDigit(v[1])) v = v[1..];
        var colon = v.IndexOf(':');
        if (colon > 0 && v[..colon].All(char.IsDigit)) v = v[(colon + 1)..];
        var plus = v.IndexOf('+');
        if (plus > 0) v = v[..plus];
        return v;
    }

    public static bool IsWildcard(string? version) =>
        string.IsNullOrWhiteSpace(version) || version is "*" or "-" or "N/A" or "n/a" or "0";

    /// <summary>Nombre de segments numériques de tête (ex. "11.4" = 2).</summary>
    public static int NumericDepth(string? version)
    {
        var parts = Clean(version).Split('.', '-', '_');
        var n = 0;
        foreach (var p in parts)
        {
            if (p.Length > 0 && p.All(char.IsDigit)) n++;
            else break;
        }
        return n;
    }

    /// <summary>Compare deux versions. Retourne &lt;0, 0, &gt;0.</summary>
    public static int Compare(string? a, string? b)
    {
        var ta = Tokenize(Clean(a));
        var tb = Tokenize(Clean(b));
        var n = Math.Max(ta.Count, tb.Count);
        for (var i = 0; i < n; i++)
        {
            var x = i < ta.Count ? ta[i] : null;
            var y = i < tb.Count ? tb[i] : null;
            if (x is null && y is null) return 0;

            // Segment manquant : "1.2" == "1.2.0" ; "1.2" > "1.2-rc1" (pré-version)
            if (x is null)
            {
                if (y!.IsNumber && y.Number == 0) continue;
                return y.IsNumber ? -1 : 1;
            }
            if (y is null)
            {
                if (x.IsNumber && x.Number == 0) continue;
                return x.IsNumber ? 1 : -1;
            }

            if (x.IsNumber && y.IsNumber)
            {
                var c = x.Number.CompareTo(y.Number);
                if (c != 0) return c;
            }
            else if (x.IsNumber != y.IsNumber)
            {
                // Un nombre est plus grand qu'un suffixe de pré-version (1.0.0 > 1.0.rc)
                return x.IsNumber ? 1 : -1;
            }
            else
            {
                var c = PreReleaseRank(x.Text).CompareTo(PreReleaseRank(y.Text));
                if (c == 0) c = string.Compare(x.Text, y.Text, StringComparison.OrdinalIgnoreCase);
                if (c != 0) return c;
            }
        }
        return 0;
    }

    public static bool AreEqual(string? a, string? b) => Compare(a, b) == 0;

    /// <summary>"11.4" est-il un préfixe de "11.4.2" ?</summary>
    public static bool IsPrefixOf(string? prefix, string? full)
    {
        var p = Clean(prefix);
        var f = Clean(full);
        if (p.Length == 0) return true;
        return f.Equals(p, StringComparison.OrdinalIgnoreCase) || f.StartsWith(p + ".", StringComparison.OrdinalIgnoreCase)
               || f.StartsWith(p + "-", StringComparison.OrdinalIgnoreCase);
    }

    private static int PreReleaseRank(string s) => s.ToLowerInvariant() switch
    {
        "dev" or "snapshot" => 0,
        "alpha" or "a" => 1,
        "beta" or "b" => 2,
        "pre" or "preview" => 3,
        "rc" or "cr" => 4,
        "final" or "ga" or "release" => 6,
        _ => 5
    };

    private sealed record Token(bool IsNumber, long Number, string Text);

    private static List<Token> Tokenize(string v)
    {
        var list = new List<Token>();
        foreach (Match m in TokenRegex().Matches(v))
        {
            if (long.TryParse(m.Value, out var n)) list.Add(new Token(true, n, m.Value));
            else list.Add(new Token(false, 0, m.Value));
        }
        return list;
    }
}
