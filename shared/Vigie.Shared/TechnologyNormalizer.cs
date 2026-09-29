using System.Text.RegularExpressions;

namespace Vigie.Shared;

/// <summary>Technologie après normalisation d'une ligne saisie par l'utilisateur.</summary>
public sealed class NormalizedTechnology : ITechnologyTarget
{
    public string Name { get; set; } = "";
    public string Type { get; set; } = TechTypes.Other;
    public string Vendor { get; set; } = "";
    public string Product { get; set; } = "";
    public string Version { get; set; } = "";
    public string Ecosystem { get; set; } = "";
    public string? PackageName { get; set; }
    public string? Cpe { get; set; }
    public string? Keywords { get; set; }
    public string? SourceLine { get; set; }
    public bool KnownProduct { get; set; }
    /// <summary>Solutions (applications) qui utilisent cette technologie : section "[PAC+]" ou option "| solution=A,B".</summary>
    public string[] Solutions { get; set; } = [];
}

public static class TechTypes
{
    public const string Os = "os", Framework = "framework", Runtime = "runtime", Library = "library",
        Database = "database", WebServer = "webserver", DockerImage = "docker_image", Application = "application", Other = "other";

    public static readonly string[] All = [Os, Framework, Runtime, Library, Database, WebServer, DockerImage, Application, Other];
}

/// <summary>
/// Transforme "npm:react@18.2.0", "PHP 8.1.2", "docker:nginx:1.25-alpine"... en technologie
/// normalisée (vendeur/produit CPE, écosystème OSV, version). Un catalogue d'alias couvre
/// les produits courants ; sinon le nom est utilisé tel quel et la CPE peut être forcée
/// avec l'option "| cpe=...".
/// </summary>
public static partial class TechnologyNormalizer
{
    private sealed record Alias(string Vendor, string Product, string Part, string Type, string Display);

    // Clés : nom en minuscules. Valeurs : vendeur/produit du dictionnaire CPE du NVD.
    private static readonly Dictionary<string, Alias> Catalog = new(StringComparer.OrdinalIgnoreCase)
    {
        // Systèmes d'exploitation
        ["ubuntu"] = new("canonical", "ubuntu_linux", "o", TechTypes.Os, "Ubuntu"),
        ["debian"] = new("debian", "debian_linux", "o", TechTypes.Os, "Debian"),
        ["alpine"] = new("alpinelinux", "alpine_linux", "o", TechTypes.Os, "Alpine Linux"),
        ["rhel"] = new("redhat", "enterprise_linux", "o", TechTypes.Os, "Red Hat Enterprise Linux"),
        ["red hat enterprise linux"] = new("redhat", "enterprise_linux", "o", TechTypes.Os, "Red Hat Enterprise Linux"),
        ["windows server 2016"] = new("microsoft", "windows_server_2016", "o", TechTypes.Os, "Windows Server 2016"),
        ["windows server 2019"] = new("microsoft", "windows_server_2019", "o", TechTypes.Os, "Windows Server 2019"),
        ["windows server 2022"] = new("microsoft", "windows_server_2022", "o", TechTypes.Os, "Windows Server 2022"),
        ["windows server 2025"] = new("microsoft", "windows_server_2025", "o", TechTypes.Os, "Windows Server 2025"),
        ["windows 10"] = new("microsoft", "windows_10", "o", TechTypes.Os, "Windows 10"),
        ["linux kernel"] = new("linux", "linux_kernel", "o", TechTypes.Os, "Noyau Linux"),
        ["vmware esxi"] = new("vmware", "esxi", "o", TechTypes.Os, "VMware ESXi"),
        ["esxi"] = new("vmware", "esxi", "o", TechTypes.Os, "VMware ESXi"),
        ["fortios"] = new("fortinet", "fortios", "o", TechTypes.Os, "Fortinet FortiOS"),

        // Runtimes / frameworks Microsoft
        [".net"] = new("microsoft", ".net", "a", TechTypes.Runtime, ".NET"),
        ["dotnet"] = new("microsoft", ".net", "a", TechTypes.Runtime, ".NET"),
        [".net core"] = new("microsoft", ".net_core", "a", TechTypes.Runtime, ".NET Core"),
        ["asp.net core"] = new("microsoft", "asp.net_core", "a", TechTypes.Framework, "ASP.NET Core"),
        ["aspnetcore"] = new("microsoft", "asp.net_core", "a", TechTypes.Framework, "ASP.NET Core"),
        [".net framework"] = new("microsoft", ".net_framework", "a", TechTypes.Framework, ".NET Framework"),
        ["asp.net"] = new("microsoft", "asp.net", "a", TechTypes.Framework, "ASP.NET"),
        ["iis"] = new("microsoft", "internet_information_services", "a", TechTypes.WebServer, "IIS"),
        ["sql server"] = new("microsoft", "sql_server", "a", TechTypes.Database, "SQL Server"),
        ["mssql"] = new("microsoft", "sql_server", "a", TechTypes.Database, "SQL Server"),
        ["exchange server"] = new("microsoft", "exchange_server", "a", TechTypes.Application, "Exchange Server"),
        ["sharepoint"] = new("microsoft", "sharepoint_server", "a", TechTypes.Application, "SharePoint Server"),
        ["powershell"] = new("microsoft", "powershell", "a", TechTypes.Runtime, "PowerShell"),
        ["newtonsoft.json"] = new("newtonsoft", "json.net", "a", TechTypes.Library, "Newtonsoft.Json"),

        // Langages / runtimes
        ["php"] = new("php", "php", "a", TechTypes.Runtime, "PHP"),
        ["node.js"] = new("nodejs", "node.js", "a", TechTypes.Runtime, "Node.js"),
        ["nodejs"] = new("nodejs", "node.js", "a", TechTypes.Runtime, "Node.js"),
        ["node"] = new("nodejs", "node.js", "a", TechTypes.Runtime, "Node.js"),
        ["python"] = new("python", "python", "a", TechTypes.Runtime, "Python"),
        ["java"] = new("oracle", "jdk", "a", TechTypes.Runtime, "Java JDK"),
        ["openjdk"] = new("oracle", "openjdk", "a", TechTypes.Runtime, "OpenJDK"),
        ["go"] = new("golang", "go", "a", TechTypes.Runtime, "Go"),
        ["ruby"] = new("ruby-lang", "ruby", "a", TechTypes.Runtime, "Ruby"),

        // Serveurs web / applicatifs
        ["nginx"] = new("f5", "nginx", "a", TechTypes.WebServer, "nginx"),
        ["apache"] = new("apache", "http_server", "a", TechTypes.WebServer, "Apache HTTP Server"),
        ["apache http server"] = new("apache", "http_server", "a", TechTypes.WebServer, "Apache HTTP Server"),
        ["httpd"] = new("apache", "http_server", "a", TechTypes.WebServer, "Apache HTTP Server"),
        ["tomcat"] = new("apache", "tomcat", "a", TechTypes.WebServer, "Apache Tomcat"),
        ["traefik"] = new("traefik", "traefik", "a", TechTypes.WebServer, "Traefik"),

        // Bases de données
        ["postgresql"] = new("postgresql", "postgresql", "a", TechTypes.Database, "PostgreSQL"),
        ["postgres"] = new("postgresql", "postgresql", "a", TechTypes.Database, "PostgreSQL"),
        ["mariadb"] = new("mariadb", "mariadb", "a", TechTypes.Database, "MariaDB"),
        ["mysql"] = new("oracle", "mysql", "a", TechTypes.Database, "MySQL"),
        ["mongodb"] = new("mongodb", "mongodb", "a", TechTypes.Database, "MongoDB"),
        ["redis"] = new("redis", "redis", "a", TechTypes.Database, "Redis"),
        ["elasticsearch"] = new("elastic", "elasticsearch", "a", TechTypes.Database, "Elasticsearch"),

        // Applications
        ["wordpress"] = new("wordpress", "wordpress", "a", TechTypes.Application, "WordPress"),
        ["drupal"] = new("drupal", "drupal", "a", TechTypes.Application, "Drupal"),
        ["moodle"] = new("moodle", "moodle", "a", TechTypes.Application, "Moodle"),
        ["phpmyadmin"] = new("phpmyadmin", "phpmyadmin", "a", TechTypes.Application, "phpMyAdmin"),
        ["jenkins"] = new("jenkins", "jenkins", "a", TechTypes.Application, "Jenkins"),
        ["gitlab"] = new("gitlab", "gitlab", "a", TechTypes.Application, "GitLab"),
        ["keycloak"] = new("redhat", "keycloak", "a", TechTypes.Application, "Keycloak"),
        ["grafana"] = new("grafana", "grafana", "a", TechTypes.Application, "Grafana"),
        ["ollama"] = new("ollama", "ollama", "a", TechTypes.Application, "Ollama"),
        ["docker"] = new("docker", "docker", "a", TechTypes.Runtime, "Docker"),
        ["kubernetes"] = new("kubernetes", "kubernetes", "a", TechTypes.Runtime, "Kubernetes"),
        ["git"] = new("git-scm", "git", "a", TechTypes.Application, "Git"),
        ["7-zip"] = new("7-zip", "7-zip", "a", TechTypes.Application, "7-Zip"),

        // Bibliothèques
        ["jquery"] = new("jquery", "jquery", "a", TechTypes.Library, "jQuery"),
        ["jquery ui"] = new("jqueryui", "jquery_ui", "a", TechTypes.Library, "jQuery UI"),
        ["bootstrap"] = new("getbootstrap", "bootstrap", "a", TechTypes.Library, "Bootstrap"),
        ["react"] = new("facebook", "react", "a", TechTypes.Library, "React"),
        ["vue"] = new("vuejs", "vue.js", "a", TechTypes.Library, "Vue.js"),
        ["vite"] = new("vitejs", "vite", "a", TechTypes.Library, "Vite"),
        ["lodash"] = new("lodash", "lodash", "a", TechTypes.Library, "Lodash"),
        ["axios"] = new("axios", "axios", "a", TechTypes.Library, "Axios"),
        ["express"] = new("expressjs", "express", "a", TechTypes.Framework, "Express"),
        ["laravel"] = new("laravel", "framework", "a", TechTypes.Framework, "Laravel"),
        ["symfony"] = new("sensiolabs", "symfony", "a", TechTypes.Framework, "Symfony"),
        ["spring framework"] = new("vmware", "spring_framework", "a", TechTypes.Framework, "Spring Framework"),
        ["log4j"] = new("apache", "log4j", "a", TechTypes.Library, "Apache Log4j"),
        ["openssl"] = new("openssl", "openssl", "a", TechTypes.Library, "OpenSSL"),
        ["openssh"] = new("openbsd", "openssh", "a", TechTypes.Application, "OpenSSH"),
        ["curl"] = new("haxx", "curl", "a", TechTypes.Library, "curl"),
        ["libcurl"] = new("haxx", "libcurl", "a", TechTypes.Library, "libcurl"),
        ["glibc"] = new("gnu", "glibc", "a", TechTypes.Library, "glibc"),
        ["sudo"] = new("sudo_project", "sudo", "a", TechTypes.Application, "sudo"),
        ["guzzlehttp/guzzle"] = new("guzzlephp", "guzzle", "a", TechTypes.Library, "Guzzle"),
    };

    // Préfixes de type
    private static readonly Dictionary<string, string> TypePrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["os"] = TechTypes.Os, ["framework"] = TechTypes.Framework, ["fw"] = TechTypes.Framework,
        ["runtime"] = TechTypes.Runtime, ["lib"] = TechTypes.Library, ["library"] = TechTypes.Library,
        ["database"] = TechTypes.Database, ["db"] = TechTypes.Database, ["web"] = TechTypes.WebServer,
        ["webserver"] = TechTypes.WebServer, ["app"] = TechTypes.Application, ["application"] = TechTypes.Application,
        ["docker"] = TechTypes.DockerImage, ["image"] = TechTypes.DockerImage, ["other"] = TechTypes.Other,
    };

    // Préfixes d'écosystème -> nom d'écosystème OSV (https://ossf.github.io/osv-schema/#affectedpackage-field)
    private static readonly Dictionary<string, string> EcosystemPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["npm"] = "npm", ["nuget"] = "NuGet", ["pypi"] = "PyPI", ["pip"] = "PyPI", ["composer"] = "Packagist",
        ["packagist"] = "Packagist", ["maven"] = "Maven", ["go"] = "Go", ["golang"] = "Go", ["cargo"] = "crates.io",
        ["crates"] = "crates.io", ["gem"] = "RubyGems", ["rubygems"] = "RubyGems", ["debian"] = "Debian",
        ["deb"] = "Debian", ["ubuntu"] = "Ubuntu", ["alpine"] = "Alpine", ["apk"] = "Alpine",
    };

    public static string NormalizeEcosystem(string? eco)
    {
        if (string.IsNullOrWhiteSpace(eco)) return "";
        return EcosystemPrefixes.TryGetValue(eco.Trim(), out var e) ? e : eco.Trim();
    }

    [GeneratedRegex(@"^(?<name>.+?)\s+v?(?<ver>\d[\w.\-+]*)$")]
    private static partial Regex NameSpaceVersion();

    [GeneratedRegex(@"^\d+(\.\d+)*")]
    private static partial Regex LeadingVersion();

    /// <summary>
    /// Analyse un texte multiligne ; ignore lignes vides et commentaires (#).
    /// Une ligne "[Solution]" affecte les lignes suivantes à cette solution ("[]" : plus de solution).
    /// </summary>
    public static List<(int LineNumber, NormalizedTechnology? Tech, string? Error)> ParseMany(string text)
    {
        var result = new List<(int, NormalizedTechnology?, string?)>();
        var lines = text.Replace("\r", "").Split('\n');
        string? section = null;
        for (var i = 0; i < lines.Length; i++)
        {
            var l = lines[i].Trim();
            if (l.Length == 0 || l.StartsWith('#') || l.StartsWith("//")) continue;
            if (l.StartsWith('[') && l.EndsWith(']'))
            {
                section = NormalizeSolution(l[1..^1]);
                continue;
            }
            try
            {
                var tech = ParseLine(l);
                if (tech.Solutions.Length == 0 && section is { Length: > 0 }) tech.Solutions = [section];
                result.Add((i + 1, tech, null));
            }
            catch (FormatException ex) { result.Add((i + 1, null, ex.Message)); }
        }
        return result;
    }

    /// <summary>"PAC+ , Intranet,pac+" -> ["PAC+", "Intranet"] (sans doublon, casse de la première occurrence).</summary>
    public static string[] ParseSolutions(string? value) =>
        (value ?? "").Split(',').Select(NormalizeSolution).Where(s => s.Length > 0)
            .DistinctBy(s => s.ToLowerInvariant()).ToArray();

    private static string NormalizeSolution(string s)
    {
        var t = WhiteSpaces().Replace(s.Trim(), " ");
        return t.Length > 100 ? t[..100] : t;
    }

    [GeneratedRegex(@"\s+")]
    private static partial Regex WhiteSpaces();

    public static NormalizedTechnology ParseLine(string line)
    {
        var segments = line.Split('|');
        var spec = segments[0].Trim();
        var options = segments.Skip(1)
            .Select(s => s.Split('=', 2))
            .Where(kv => kv.Length == 2)
            .ToDictionary(kv => kv[0].Trim().ToLowerInvariant(), kv => kv[1].Trim());

        if (spec.Length == 0) throw new FormatException("Ligne vide");

        var tech = new NormalizedTechnology { SourceLine = line.Length > 500 ? line[..500] : line };
        string? typeFromPrefix = null;
        string? ecosystem = null;

        // Préfixe "xxx:" (sauf si ce qui suit est un chiffre, ex. "nom:1.2")
        var colon = spec.IndexOf(':');
        if (colon > 0)
        {
            var prefix = spec[..colon].Trim();
            if (TypePrefixes.TryGetValue(prefix, out var t)) { typeFromPrefix = t; spec = spec[(colon + 1)..].Trim(); }
            else if (EcosystemPrefixes.TryGetValue(prefix, out var e)) { ecosystem = e; spec = spec[(colon + 1)..].Trim(); }
        }

        string name;
        var version = "";
        var extraKeywords = new List<string>();

        if (typeFromPrefix == TechTypes.DockerImage)
        {
            // image[:tag] -> registre/chemin retiré, tag = version
            var at = spec.LastIndexOf(':');
            var image = at > 0 ? spec[..at] : spec;
            var tag = at > 0 ? spec[(at + 1)..] : "latest";
            name = image.Split('/').Last();
            var m = LeadingVersion().Match(tag);
            version = m.Success ? m.Value : "";
            var suffix = m.Success ? tag[m.Length..].Trim('-', '.') : tag;
            if (!string.IsNullOrEmpty(suffix) && suffix != "latest") extraKeywords.Add(suffix);
            tech.Name = $"{name}:{tag} (image Docker)";
        }
        else
        {
            var at = spec.LastIndexOf('@');
            if (at > 0) { name = spec[..at].Trim(); version = spec[(at + 1)..].Trim(); }
            else
            {
                var m = NameSpaceVersion().Match(spec);
                if (m.Success && !Catalog.ContainsKey(spec)) { name = m.Groups["name"].Value.Trim(); version = m.Groups["ver"].Value; }
                else name = spec;
            }
        }

        if (string.IsNullOrWhiteSpace(name)) throw new FormatException($"Nom manquant : « {line} »");

        var lookup = name.Trim().ToLowerInvariant();
        Catalog.TryGetValue(lookup, out var alias);
        tech.Version = version.Length > 100 ? version[..100] : version;
        tech.Ecosystem = NormalizeEcosystem(options.GetValueOrDefault("ecosystem") ?? ecosystem);
        tech.PackageName = tech.Ecosystem.Length > 0 ? (options.GetValueOrDefault("package") ?? name.Trim()) : null;

        if (alias is not null)
        {
            tech.Vendor = alias.Vendor;
            tech.Product = alias.Product;
            tech.KnownProduct = true;
            tech.Type = typeFromPrefix ?? (tech.Ecosystem.Length > 0 ? TechTypes.Library : alias.Type);
            if (string.IsNullOrEmpty(tech.Name)) tech.Name = alias.Display;
            tech.Cpe = CpeName.Build(alias.Part, alias.Vendor, alias.Product, NullIfEmpty(tech.Version));
        }
        else
        {
            tech.Vendor = "";
            tech.Product = Correlator.Norm(name.Split('/').Last().TrimStart('@'));
            tech.Type = typeFromPrefix ?? (tech.Ecosystem.Length > 0 ? TechTypes.Library : TechTypes.Other);
            if (string.IsNullOrEmpty(tech.Name)) tech.Name = name.Trim();
        }

        // Options explicites (priorité sur le catalogue)
        if (options.TryGetValue("name", out var n) && n.Length > 0) tech.Name = n;
        if (options.TryGetValue("type", out var ty) && TechTypes.All.Contains(ty.ToLowerInvariant())) tech.Type = ty.ToLowerInvariant();
        if (options.TryGetValue("vendor", out var v)) tech.Vendor = Correlator.Norm(v);
        if (options.TryGetValue("product", out var p)) tech.Product = Correlator.Norm(p);
        if (options.TryGetValue("keywords", out var k)) extraKeywords.AddRange(k.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));
        if (options.TryGetValue("solution", out var sol) || options.TryGetValue("solutions", out sol)) tech.Solutions = ParseSolutions(sol);
        if (options.TryGetValue("cpe", out var cpe))
        {
            var parsed = CpeName.Parse(cpe) ?? throw new FormatException($"CPE invalide : {cpe}");
            tech.Cpe = cpe;
            tech.Vendor = parsed.Vendor;
            tech.Product = parsed.Product;
            tech.KnownProduct = true;
            if (string.IsNullOrEmpty(tech.Version) && !VersionComparer.IsWildcard(parsed.Version)) tech.Version = parsed.Version;
        }
        else if (options.ContainsKey("vendor") || options.ContainsKey("product"))
        {
            tech.KnownProduct = tech.Vendor.Length > 0;
            tech.Cpe = tech.Vendor.Length > 0 ? CpeName.Build(tech.Type == TechTypes.Os ? "o" : "a", tech.Vendor, tech.Product, NullIfEmpty(tech.Version)) : null;
        }

        if (extraKeywords.Count > 0) tech.Keywords = string.Join(",", extraKeywords.Distinct());
        if (tech.Name.Length > 200) tech.Name = tech.Name[..200];
        return tech;
    }

    /// <summary>Normalise une technologie saisie par formulaire (champs séparés).</summary>
    public static NormalizedTechnology FromFields(string name, string? type, string? vendor, string? product,
        string? version, string? ecosystem, string? packageName, string? cpe, string? keywords)
    {
        var line = (ecosystem is { Length: > 0 } ? $"{ecosystem}:" : type is { Length: > 0 } && type != TechTypes.Other ? $"{TypeToPrefix(type)}:" : "")
                   + (packageName is { Length: > 0 } ? packageName : name)
                   + (version is { Length: > 0 } ? $"@{version}" : "");
        var opts = new List<string>();
        if (!string.IsNullOrWhiteSpace(cpe)) opts.Add($"cpe={cpe.Trim()}");
        if (!string.IsNullOrWhiteSpace(vendor)) opts.Add($"vendor={vendor.Trim()}");
        if (!string.IsNullOrWhiteSpace(product)) opts.Add($"product={product.Trim()}");
        if (!string.IsNullOrWhiteSpace(keywords)) opts.Add($"keywords={keywords.Trim()}");
        if (!string.IsNullOrWhiteSpace(type)) opts.Add($"type={type.Trim()}");
        opts.Add($"name={name.Trim()}");
        if (type == TechTypes.DockerImage && ecosystem is not { Length: > 0 })
            line = $"docker:{name}{(version is { Length: > 0 } ? ":" + version : "")}";
        return ParseLine(string.Join(" | ", new[] { line }.Concat(opts)));
    }

    /// <summary>
    /// Inverse de <see cref="ParseLine"/> : ligne au format config/stack.txt qui redonne cette technologie
    /// à l'import. On écrit la forme courte ("npm:react@19.2.5"), puis on n'ajoute une option
    /// (name=, cpe=, product=...) que si la normalisation de cette forme courte ne retombe pas sur les mêmes champs.
    /// </summary>
    public static string ToLine(string name, string type, string vendor, string product, string version,
        string ecosystem, string? packageName, string? cpe, string? keywords)
    {
        var eco = ecosystem;
        var ecoPrefix = eco.Length > 0 ? EcosystemPrefixes.FirstOrDefault(kv => kv.Value == eco).Key : null;

        string spec;
        if (type == TechTypes.DockerImage && eco.Length == 0)
            spec = "docker:" + DockerSuffix().Replace(name, "");
        else
        {
            var prefix = ecoPrefix ?? (eco.Length > 0 || type == TechTypes.Other ? null : TypeToPrefix(type));
            var baseName = eco.Length > 0 && !string.IsNullOrEmpty(packageName) ? packageName : name;
            spec = (prefix is null ? "" : prefix + ":") + baseName + (version.Length > 0 ? "@" + version : "");
        }

        var opts = new List<string>();
        if (eco.Length > 0 && ecoPrefix is null) opts.Add($"ecosystem={eco}");
        var n = Parse(spec, opts);

        if (n.Name != name) opts.Add($"name={name}");
        if (n.Type != type) opts.Add($"type={type}");
        if (!string.IsNullOrEmpty(cpe))
        {
            if (n.Cpe != cpe) opts.Add($"cpe={cpe}");
        }
        else
        {
            if (n.Vendor != vendor && vendor.Length > 0) opts.Add($"vendor={vendor}");
            if (n.Product != product && product.Length > 0) opts.Add($"product={product}");
        }
        if (!string.IsNullOrEmpty(keywords) && n.Keywords != keywords) opts.Add($"keywords={keywords}");

        return string.Join(" | ", new[] { spec }.Concat(opts));

        static NormalizedTechnology Parse(string spec, List<string> opts) =>
            ParseLine(string.Join(" | ", new[] { spec }.Concat(opts)));
    }

    [GeneratedRegex(@" \(image Docker\)$")]
    private static partial Regex DockerSuffix();

    private static string TypeToPrefix(string type) => type switch
    {
        TechTypes.WebServer => "web",
        TechTypes.DockerImage => "docker",
        TechTypes.Library => "lib",
        TechTypes.Application => "app",
        var t => t
    };

    private static string? NullIfEmpty(string? s) => string.IsNullOrWhiteSpace(s) ? null : s;
}
