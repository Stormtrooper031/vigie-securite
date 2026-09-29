using System.Globalization;
using System.Text.Json;

namespace Vigie.Scanner.Sources;

/// <summary>Lecture tolérante de JSON (les flux publics ont des champs optionnels).</summary>
internal static class JsonExt
{
    public static JsonElement? Prop(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null ? v : null;

    public static string? Str(this JsonElement e, string name) =>
        e.Prop(name) is { } v ? v.ValueKind == JsonValueKind.String ? v.GetString() : v.ToString() : null;

    public static bool Bool(this JsonElement e, string name) =>
        e.Prop(name) is { ValueKind: JsonValueKind.True };

    public static decimal? Dec(this JsonElement e, string name)
    {
        if (e.Prop(name) is not { } v) return null;
        if (v.ValueKind == JsonValueKind.Number && v.TryGetDecimal(out var d)) return d;
        if (v.ValueKind == JsonValueKind.String && decimal.TryParse(v.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var s)) return s;
        return null;
    }

    public static IEnumerable<JsonElement> Arr(this JsonElement e, string name) =>
        e.Prop(name) is { ValueKind: JsonValueKind.Array } a ? a.EnumerateArray() : [];

    public static DateTime? Date(this JsonElement e, string name)
    {
        var s = e.Str(name);
        if (string.IsNullOrWhiteSpace(s)) return null;
        return DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d)
            ? DateTime.SpecifyKind(d, DateTimeKind.Utc)
            : null;
    }

    public static string Trunc(this string s, int max) => s.Length <= max ? s : s[..max];

    /// <summary>Titre court tiré de la description (première phrase).</summary>
    public static string? TitleFrom(string? description)
    {
        if (string.IsNullOrWhiteSpace(description)) return null;
        var d = description.Trim().Replace('\n', ' ');
        var dot = d.IndexOf(". ", StringComparison.Ordinal);
        var t = dot > 20 && dot < 200 ? d[..dot] : d;
        return t.Length > 200 ? t[..197] + "..." : t;
    }
}
