namespace Vigie.Shared;

/// <summary>Lecture / construction de chaînes CPE 2.3 (cpe:2.3:part:vendor:product:version:...).</summary>
public sealed record CpeName(string Part, string Vendor, string Product, string Version)
{
    public static CpeName? Parse(string? cpe)
    {
        if (string.IsNullOrWhiteSpace(cpe) || !cpe.StartsWith("cpe:2.3:", StringComparison.OrdinalIgnoreCase)) return null;
        var fields = SplitEscaped(cpe);
        if (fields.Count < 6) return null;
        return new CpeName(fields[2], Unescape(fields[3]).ToLowerInvariant(), Unescape(fields[4]).ToLowerInvariant(), Unescape(fields[5]));
    }

    public static string Build(string part, string? vendor, string product, string? version = null)
    {
        var v = string.IsNullOrWhiteSpace(vendor) ? "*" : Escape(vendor);
        var ver = string.IsNullOrWhiteSpace(version) ? "*" : Escape(version);
        return $"cpe:2.3:{part}:{v}:{Escape(product)}:{ver}:*:*:*:*:*:*:*";
    }

    /// <summary>Chaîne de recherche NVD (virtualMatchString) sans version : cpe:2.3:a:vendor:product</summary>
    public static string MatchString(string part, string vendor, string product) =>
        $"cpe:2.3:{part}:{Escape(vendor)}:{Escape(product)}";

    private static List<string> SplitEscaped(string s)
    {
        var list = new List<string>();
        var cur = new System.Text.StringBuilder();
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] == '\\' && i + 1 < s.Length) { cur.Append(s[i]).Append(s[i + 1]); i++; continue; }
            if (s[i] == ':') { list.Add(cur.ToString()); cur.Clear(); continue; }
            cur.Append(s[i]);
        }
        list.Add(cur.ToString());
        return list;
    }

    private static string Unescape(string s) => s.Replace("\\", "");

    private static string Escape(string s)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var c in s.Trim().ToLowerInvariant().Replace(' ', '_'))
        {
            if (char.IsLetterOrDigit(c) || c is '_' or '.' or '-') sb.Append(c);
            else sb.Append('\\').Append(c);
        }
        return sb.ToString();
    }
}
