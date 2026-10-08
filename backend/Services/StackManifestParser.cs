using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Vigie.Api.Services;

/// <summary>Technologies déduites des fichiers d'un dépôt, sous forme de lignes au format config/stack.txt.</summary>
public sealed class ManifestResult
{
    public HashSet<string> Lines { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Warnings { get; } = [];
    public List<string> Files { get; } = [];
}

/// <summary>
/// Déduit la stack d'un dépôt à partir de ses fichiers de dépendances : .csproj / packages.config / Directory.Packages.props,
/// package.json (+ package-lock.json), requirements*.txt, composer.json (+ composer.lock), pom.xml, go.mod,
/// Dockerfile, docker-compose, libman.json, .nvmrc, .python-version.
/// Les versions exactes sont privilégiées (fichiers lock) ; sinon la version indiquée est nettoyée (^1.2.3 -> 1.2.3).
/// </summary>
public static partial class StackManifestParser
{
    private const int MaxFiles = 300;
    private static readonly string[] IgnoredDirs = ["node_modules", "bin", "obj", ".git", "dist", ".vs", "vendor", "bower_components", ".angular"];
    private static readonly string[] UnsupportedFiles = ["build.gradle", "build.gradle.kts", "cargo.toml", "gemfile", "pyproject.toml", "pipfile"];
    private static readonly JsonDocumentOptions Lenient = new() { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip };

    public static async Task<ManifestResult> AnalyzeAsync(IEnumerable<string> allPaths, Func<string, Task<string?>> read)
    {
        var result = new ManifestResult();
        var paths = allPaths.Where(p => !p.Split('/').SkipLast(1).Any(s => IgnoredDirs.Contains(s, StringComparer.OrdinalIgnoreCase))).ToList();

        foreach (var g in paths.Where(p => UnsupportedFiles.Contains(Path.GetFileName(p).ToLowerInvariant()))
                     .GroupBy(p => Path.GetFileName(p).ToLowerInvariant()))
            result.Warnings.Add($"{g.Key} non pris en charge ({g.Count()} fichier(s) ignoré(s)) : ajoutez ces technologies à la main.");

        var wanted = paths.Where(p => Kind(p) != null).Take(MaxFiles).ToList();
        if (paths.Count(p => Kind(p) != null) > MaxFiles)
            result.Warnings.Add($"Plus de {MaxFiles} fichiers de dépendances : seuls les {MaxFiles} premiers sont lus.");

        var content = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var gate = new SemaphoreSlim(6);
        await Task.WhenAll(wanted.Select(async p =>
        {
            await gate.WaitAsync();
            try
            {
                var text = await read(p);
                if (text is not null) lock (content) content[p] = text;
            }
            finally { gate.Release(); }
        }));

        foreach (var path in wanted.Where(content.ContainsKey).Order(StringComparer.OrdinalIgnoreCase))
        {
            try { ParseFile(path, Kind(path)!, content, result); }
            catch (Exception ex) when (ex is JsonException or System.Xml.XmlException or FormatException or KeyNotFoundException or InvalidOperationException)
            {
                result.Warnings.Add($"{path} illisible : {ex.Message}");
            }
            result.Files.Add(path);
        }
        return result;
    }

    /// <summary>Type d'analyse pour un fichier (null = ignoré). Les fichiers lock servent de complément, pas de point d'entrée.</summary>
    private static string? Kind(string path)
    {
        var n = Path.GetFileName(path).ToLowerInvariant();
        if (n.EndsWith(".csproj") || n.EndsWith(".vbproj") || n.EndsWith(".fsproj")) return "csproj";
        if (n == "packages.config") return "packages.config";
        if (n == "package.json") return "npm";
        if (n.StartsWith("requirements") && n.EndsWith(".txt")) return "pip";
        if (n == "composer.json") return "composer";
        if (n == "pom.xml") return "maven";
        if (n == "go.mod") return "go";
        if (n == "dockerfile" || n.StartsWith("dockerfile.") || n.EndsWith(".dockerfile")) return "dockerfile";
        if ((n.StartsWith("docker-compose") || n.StartsWith("compose")) && (n.EndsWith(".yml") || n.EndsWith(".yaml"))) return "compose";
        if (n == "libman.json") return "libman";
        if (n is ".nvmrc" or ".node-version") return "node-version";
        if (n == ".python-version") return "python-version";
        // Compléments lus avec leur manifeste
        if (n is "directory.packages.props" or "package-lock.json" or "composer.lock") return "companion";
        return null;
    }

    private static void ParseFile(string path, string kind, Dictionary<string, string> files, ManifestResult r)
    {
        var text = files[path];
        switch (kind)
        {
            case "csproj": ParseCsproj(path, text, files, r); break;
            case "packages.config": ParsePackagesConfig(text, r); break;
            case "npm": ParsePackageJson(path, text, files, r); break;
            case "pip": ParseRequirements(path, text, r); break;
            case "composer": ParseComposer(path, text, files, r); break;
            case "maven": ParsePom(text, r); break;
            case "go": ParseGoMod(text, r); break;
            case "dockerfile": ParseDockerfile(text, r); break;
            case "compose": ParseCompose(text, r); break;
            case "libman": ParseLibman(text, r); break;
            case "node-version": AddVersion(r, "runtime:Node.js", text.Trim().TrimStart('v'), exact: false); break;
            case "python-version": AddVersion(r, "runtime:Python", text.Trim(), exact: false); break;
        }
    }

    // ---------------------------------------------------------------- .NET

    private static void ParseCsproj(string path, string text, Dictionary<string, string> files, ManifestResult r)
    {
        var doc = XDocument.Parse(text);
        var all = doc.Descendants().ToList();
        var web = (doc.Root?.Attribute("Sdk")?.Value ?? "").Contains("Web", StringComparison.OrdinalIgnoreCase)
                  || (doc.Root?.Attribute("Sdk")?.Value ?? "").Contains("Razor", StringComparison.OrdinalIgnoreCase);

        var props = all.Where(e => e.Parent?.Name.LocalName == "PropertyGroup" && !e.HasElements)
            .GroupBy(e => e.Name.LocalName).ToDictionary(g => g.Key, g => g.Last().Value.Trim());

        foreach (var tfm in TargetFrameworks(props)) AddFramework(tfm, web, r);

        var central = CentralVersions(path, files);
        foreach (var pr in all.Where(e => e.Name.LocalName == "PackageReference"))
        {
            var id = (pr.Attribute("Include") ?? pr.Attribute("Update"))?.Value;
            if (string.IsNullOrWhiteSpace(id)) continue;
            var v = pr.Attribute("Version")?.Value ?? pr.Elements().FirstOrDefault(e => e.Name.LocalName == "Version")?.Value;
            v ??= pr.Attribute("VersionOverride")?.Value;
            v = Expand(v, props);
            if (string.IsNullOrWhiteSpace(v) && central.TryGetValue(id, out var cv)) v = Expand(cv, props);
            AddLib(r, "nuget", id, v, $"{path} : version introuvable pour {id}");
        }
    }

    private static IEnumerable<string> TargetFrameworks(Dictionary<string, string> props)
    {
        if (props.TryGetValue("TargetFramework", out var one)) yield return one;
        if (props.TryGetValue("TargetFrameworks", out var many))
            foreach (var t in many.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) yield return t;
        if (props.TryGetValue("TargetFrameworkVersion", out var legacy)) yield return "net" + legacy.TrimStart('v').Replace(".", "");
    }

    private static void AddFramework(string tfm, bool web, ManifestResult r)
    {
        var core = tfm.ToLowerInvariant().Split('-')[0];
        Match m;
        if ((m = Regex.Match(core, @"^net(\d+\.\d+)$")).Success)
        {
            r.Lines.Add($"runtime:.NET@{m.Groups[1].Value}");
            if (web) r.Lines.Add($"framework:ASP.NET Core@{m.Groups[1].Value}");
        }
        else if ((m = Regex.Match(core, @"^netcoreapp(\d+\.\d+)$")).Success)
        {
            r.Lines.Add($"runtime:.NET Core@{m.Groups[1].Value}");
            if (web) r.Lines.Add($"framework:ASP.NET Core@{m.Groups[1].Value}");
        }
        else if ((m = Regex.Match(core, @"^net(\d{2,3})$")).Success)
            r.Lines.Add($"framework:.NET Framework@{string.Join('.', m.Groups[1].Value.ToCharArray())}");
    }

    private static void ParsePackagesConfig(string text, ManifestResult r)
    {
        foreach (var p in XDocument.Parse(text).Descendants().Where(e => e.Name.LocalName == "package"))
        {
            if (p.Attribute("id")?.Value is not { Length: > 0 } id) continue;
            AddLib(r, "nuget", id, p.Attribute("version")?.Value, null);
            if (p.Attribute("targetFramework")?.Value is { Length: > 0 } tfm) AddFramework(tfm, false, r);
        }
    }

    /// <summary>Versions centralisées (Directory.Packages.props) du dossier le plus proche, en remontant.</summary>
    private static Dictionary<string, string> CentralVersions(string path, Dictionary<string, string> files)
    {
        var dir = path;
        while (true)
        {
            var i = dir.LastIndexOf('/');
            if (i < 0) break;
            dir = dir[..i];
            var candidate = (dir.Length == 0 ? "" : dir) + "/Directory.Packages.props";
            var key = files.Keys.FirstOrDefault(k => k.Equals(candidate, StringComparison.OrdinalIgnoreCase));
            if (key is null) continue;
            try
            {
                return XDocument.Parse(files[key]).Descendants().Where(e => e.Name.LocalName == "PackageVersion")
                    .Where(e => e.Attribute("Include") is not null && e.Attribute("Version") is not null)
                    .GroupBy(e => e.Attribute("Include")!.Value).ToDictionary(g => g.Key, g => g.Last().Attribute("Version")!.Value);
            }
            catch (System.Xml.XmlException) { return []; }
        }
        return [];
    }

    // ---------------------------------------------------------------- npm

    private static void ParsePackageJson(string path, string text, Dictionary<string, string> files, ManifestResult r)
    {
        using var pkg = JsonDocument.Parse(text, Lenient);
        var root = pkg.RootElement;
        if (root.ValueKind != JsonValueKind.Object) return;

        var lockPath = Sibling(path, "package-lock.json", files);
        JsonDocument? lockDoc = lockPath is null ? null : JsonDocument.Parse(files[lockPath], Lenient);
        using var _ = lockDoc;
        var fromRange = 0;

        foreach (var section in new[] { "dependencies", "devDependencies", "optionalDependencies" })
        {
            if (!root.TryGetProperty(section, out var deps) || deps.ValueKind != JsonValueKind.Object) continue;
            foreach (var d in deps.EnumerateObject())
            {
                var v = lockDoc is null ? null : LockedNpmVersion(lockDoc.RootElement, d.Name);
                if (v is null) { v = CleanVersion(d.Value.GetString()); if (v is not null) fromRange++; }
                AddLib(r, "npm", d.Name, v, null);
            }
        }
        if (fromRange > 0 && lockDoc is null)
            r.Warnings.Add($"{path} : pas de package-lock.json, {fromRange} version(s) tirée(s) des plages du package.json (peut différer de la version installée).");

        if (root.TryGetProperty("engines", out var eng) && eng.ValueKind == JsonValueKind.Object
            && eng.TryGetProperty("node", out var node) && CleanVersion(node.GetString()) is { } nv)
            r.Lines.Add($"runtime:Node.js@{nv}");
    }

    private static string? LockedNpmVersion(JsonElement lockRoot, string name)
    {
        if (lockRoot.TryGetProperty("packages", out var pk) && pk.TryGetProperty("node_modules/" + name, out var e)
            && e.TryGetProperty("version", out var v)) return v.GetString();
        if (lockRoot.TryGetProperty("dependencies", out var deps) && deps.TryGetProperty(name, out var d)
            && d.TryGetProperty("version", out var v1)) return v1.GetString();
        return null;
    }

    private static void ParseLibman(string text, ManifestResult r)
    {
        using var doc = JsonDocument.Parse(text, Lenient);
        if (!doc.RootElement.TryGetProperty("libraries", out var libs) || libs.ValueKind != JsonValueKind.Array) return;
        foreach (var l in libs.EnumerateArray())
        {
            var spec = l.TryGetProperty("library", out var s) ? s.GetString() : null;
            var at = spec?.LastIndexOf('@') ?? -1;
            if (spec is null || at <= 0) continue;
            AddLib(r, "lib", spec[..at], spec[(at + 1)..], null);
        }
    }

    // ---------------------------------------------------------------- Python

    private static void ParseRequirements(string path, string text, ManifestResult r)
    {
        var approx = 0;
        foreach (var raw in text.Replace("\r", "").Split('\n'))
        {
            var line = raw.Split('#')[0].Split(';')[0].Trim();
            if (line.Length == 0 || line.StartsWith('-') || line.Contains("://")) continue;
            var m = Regex.Match(line, @"^(?<n>[A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*(?<op>===|==|~=|>=|<=|>|<|!=)\s*(?<v>[^,\s]+)");
            if (!m.Success) continue;
            if (m.Groups["op"].Value is not ("==" or "===")) approx++;
            AddLib(r, "pypi", m.Groups["n"].Value, m.Groups["v"].Value.TrimEnd('*', '.'), null);
        }
        if (approx > 0) r.Warnings.Add($"{path} : {approx} dépendance(s) sans version figée (>=, ~=…) : la version minimale est utilisée.");
    }

    // ---------------------------------------------------------------- PHP

    private static void ParseComposer(string path, string text, Dictionary<string, string> files, ManifestResult r)
    {
        using var pkg = JsonDocument.Parse(text, Lenient);
        var lockPath = Sibling(path, "composer.lock", files);
        var locked = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (lockPath is not null)
        {
            using var lk = JsonDocument.Parse(files[lockPath], Lenient);
            foreach (var section in new[] { "packages", "packages-dev" })
                if (lk.RootElement.TryGetProperty(section, out var arr) && arr.ValueKind == JsonValueKind.Array)
                    foreach (var p in arr.EnumerateArray())
                        if (p.TryGetProperty("name", out var n) && p.TryGetProperty("version", out var v))
                            locked[n.GetString()!] = v.GetString()!;
        }

        foreach (var section in new[] { "require", "require-dev" })
        {
            if (!pkg.RootElement.TryGetProperty(section, out var deps) || deps.ValueKind != JsonValueKind.Object) continue;
            foreach (var d in deps.EnumerateObject())
            {
                if (d.Name.StartsWith("ext-") || d.Name.StartsWith("lib-")) continue;
                if (d.Name == "php") { AddVersion(r, "runtime:PHP", CleanVersion(d.Value.GetString()), exact: false); continue; }
                AddLib(r, "composer", d.Name, locked.GetValueOrDefault(d.Name) ?? d.Value.GetString(), null);
            }
        }
    }

    // ---------------------------------------------------------------- Java / Go

    private static void ParsePom(string text, ManifestResult r)
    {
        var doc = XDocument.Parse(text);
        var props = doc.Root?.Elements().FirstOrDefault(e => e.Name.LocalName == "properties")?.Elements()
            .GroupBy(e => e.Name.LocalName).ToDictionary(g => g.Key, g => g.Last().Value.Trim()) ?? [];

        foreach (var key in new[] { "java.version", "maven.compiler.release", "maven.compiler.source", "maven.compiler.target", "release" })
            if (props.TryGetValue(key, out var jv))
            {
                var v = CleanVersion(Expand(jv, props));
                if (v is not null) { r.Lines.Add($"runtime:Java@{(v.StartsWith("1.") ? v[2..] : v)}"); break; }
            }

        var parent = doc.Root?.Elements().FirstOrDefault(e => e.Name.LocalName == "parent");
        if (parent is not null) AddMaven(parent, props, r);
        foreach (var d in doc.Descendants().Where(e => e.Name.LocalName == "dependency")) AddMaven(d, props, r);
    }

    private static void AddMaven(XElement e, Dictionary<string, string> props, ManifestResult r)
    {
        string? Child(string n) => e.Elements().FirstOrDefault(x => x.Name.LocalName == n)?.Value.Trim();
        if (Child("groupId") is not { Length: > 0 } g || Child("artifactId") is not { Length: > 0 } a) return;
        AddLib(r, "maven", $"{g}:{a}", Expand(Child("version"), props), null);
    }

    private static void ParseGoMod(string text, ManifestResult r)
    {
        var inRequire = false;
        foreach (var raw in text.Replace("\r", "").Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("go ") && Regex.IsMatch(line, @"^go\s+\d")) { r.Lines.Add($"runtime:Go@{line[3..].Trim()}"); continue; }
            if (line.StartsWith("require (")) { inRequire = true; continue; }
            if (line == ")") { inRequire = false; continue; }
            if (line.StartsWith("require ")) line = line[8..].Trim();
            else if (!inRequire) continue;
            if (line.Contains("// indirect")) continue;
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2) AddLib(r, "go", parts[0], parts[1].TrimStart('v'), null);
        }
    }

    // ---------------------------------------------------------------- Docker

    private static void ParseDockerfile(string text, ManifestResult r)
    {
        var stages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in text.Replace("\r", "").Split('\n'))
        {
            var m = Regex.Match(raw, @"^\s*FROM\s+(--platform=\S+\s+)?(?<img>\S+)(\s+AS\s+(?<alias>\S+))?", RegexOptions.IgnoreCase);
            if (!m.Success) continue;
            var img = m.Groups["img"].Value;
            if (!stages.Contains(img)) AddImage(r, img);
            if (m.Groups["alias"].Success) stages.Add(m.Groups["alias"].Value);
        }
    }

    private static void ParseCompose(string text, ManifestResult r)
    {
        foreach (Match m in Regex.Matches(text, @"^\s*image:\s*[""']?(?<img>[^\s""'#]+)", RegexOptions.Multiline))
            AddImage(r, m.Groups["img"].Value);
    }

    /// <summary>Image avec tag précis seulement ; les images .NET de Microsoft sont déjà couvertes par le TargetFramework.</summary>
    private static void AddImage(ManifestResult r, string img)
    {
        var at = img.IndexOf('@');
        if (at > 0) img = img[..at];
        if (img is "scratch" || img.Contains('$') || img.Contains('{')) return;
        if (img.StartsWith("mcr.microsoft.com/dotnet/", StringComparison.OrdinalIgnoreCase)) return;
        var colon = img.LastIndexOf(':');
        if (colon < 0 || colon < img.LastIndexOf('/') || img[(colon + 1)..] is "latest" or "") return;
        r.Lines.Add($"docker:{img}");
    }

    // ---------------------------------------------------------------- utilitaires

    private static void AddVersion(ManifestResult r, string prefixedName, string? version, bool exact)
    {
        var v = exact ? version : CleanVersion(version);
        if (!string.IsNullOrEmpty(v)) r.Lines.Add($"{prefixedName}@{v}");
    }

    /// <summary>Ajoute "prefix:name@version" ; une version absente ou non résolue est ignorée (avertissement optionnel).</summary>
    private static void AddLib(ManifestResult r, string prefix, string name, string? version, string? warnIfMissing)
    {
        if (name.Contains('|') || name.Any(char.IsWhiteSpace)) return;
        var v = CleanVersion(version);
        if (v is null)
        {
            if (warnIfMissing is not null && !r.Warnings.Contains(warnIfMissing)) r.Warnings.Add(warnIfMissing);
            return;
        }
        r.Lines.Add($"{prefix}:{name}@{v}");
    }

    /// <summary>"^1.2.3", "~1.2", ">=1.0 &lt;2.0", "[1.0,2.0)", "1.2.*", "v18.1" -> première version numérique ; sinon null.</summary>
    public static string? CleanVersion(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var v = raw.Trim();
        if (v.Contains("$(") || v.Contains("${")) return null;
        v = v.Split("||")[0].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];
        v = v.TrimStart('^', '~', '=', '<', '>', 'v', 'V', '[', '(').Split(',')[0].TrimEnd(')', ']');
        while (v.EndsWith(".*") || v.EndsWith(".x") || v.EndsWith(".X")) v = v[..^2];
        return Regex.IsMatch(v, @"^\d[\w.\-+]*$") ? v : null;
    }

    private static string? Expand(string? v, Dictionary<string, string> props)
    {
        if (v is null) return null;
        return Regex.Replace(v, @"\$[({](?<k>[^)}]+)[)}]", m => props.GetValueOrDefault(m.Groups["k"].Value, m.Value));
    }

    /// <summary>Fichier du même dossier que <paramref name="path"/>.</summary>
    private static string? Sibling(string path, string name, Dictionary<string, string> files)
    {
        var dir = path[..(path.LastIndexOf('/') + 1)];
        return files.Keys.FirstOrDefault(k => k.Equals(dir + name, StringComparison.OrdinalIgnoreCase));
    }
}
