using System.Net;
using System.Text;
using Vigie.Api.Models;
using Vigie.Shared;

namespace Vigie.Api.Services;

public sealed class BaselineSummaryRow
{
    public string TechnologyName { get; set; } = "";
    public string TechnologyVersion { get; set; } = "";
    public int Total { get; set; }
    public int Critical { get; set; }
    public int High { get; set; }
}

/// <summary>Modèle de courriel : résumé, criticité, technologies touchées, liens CVE, action recommandée.</summary>
public static class EmailTemplateBuilder
{
    private static readonly Dictionary<string, string> Colors = new()
    {
        [Severity.Critical] = "#b91c1c",
        [Severity.High] = "#c2410c",
        [Severity.Medium] = "#a16207",
        [Severity.Low] = "#15803d",
        [Severity.Unknown] = "#475569",
        [Severity.None] = "#475569",
    };

    public static string Subject(string kind, IReadOnlyCollection<Alert> alerts, int baselineTotal)
    {
        var crit = alerts.Count(a => a.Severity == Severity.Critical);
        var kev = alerts.Count(a => a.InKev);
        var prefix = kind == "immediate" ? "[URGENT] " : "";
        if (alerts.Count == 0) return $"{prefix}Vigie sécurité : inventaire initial ({baselineTotal} failles existantes)";
        var parts = new List<string> { $"{alerts.Count} nouvelle{(alerts.Count > 1 ? "s" : "")} faille{(alerts.Count > 1 ? "s" : "")}" };
        if (crit > 0) parts.Add($"{crit} critique{(crit > 1 ? "s" : "")}");
        if (kev > 0) parts.Add($"{kev} exploitée{(kev > 1 ? "s" : "")} activement");
        return $"{prefix}Vigie sécurité : {string.Join(", ", parts)}";
    }

    private static void AppendAlertTable(StringBuilder sb, IReadOnlyList<Alert> alerts)
    {
        sb.Append("""
            <table role="presentation" width="100%" cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-size:13px">
            <tr style="background:#f8fafc;text-align:left">
              <th style="border-bottom:2px solid #e2e8f0">Criticité</th>
              <th style="border-bottom:2px solid #e2e8f0">Faille</th>
              <th style="border-bottom:2px solid #e2e8f0">Technologie</th>
              <th style="border-bottom:2px solid #e2e8f0">CVSS / EPSS</th>
              <th style="border-bottom:2px solid #e2e8f0">Action recommandée</th>
            </tr>
            """);
        foreach (var a in alerts)
        {
            var id = a.CveId ?? a.ExternalId ?? "";
            var url = a.CveId is not null ? $"https://nvd.nist.gov/vuln/detail/{a.CveId}" : $"https://osv.dev/vulnerability/{a.ExternalId}";
            var color = Colors.GetValueOrDefault(a.Severity, "#475569");
            var kevBadge = a.InKev ? $"""<br><span style="background:#7f1d1d;color:#fff;border-radius:4px;padding:1px 6px;font-size:11px">KEV{(a.KevDueDate is { } d ? $" · échéance {d:yyyy-MM-dd}" : "")}</span>""" : "";
            var action = !string.IsNullOrEmpty(a.FixedVersions)
                ? $"Mettre à jour {E(a.TechnologyName)} vers <b>{E(a.FixedVersions)}</b> ou plus"
                : "Consulter le bulletin du fournisseur (aucune version corrigée publiée)";
            var probable = a.Confidence == MatchConfidence.Probable ? "<br><i style=\"color:#64748b\">corrélation probable : vérifier la version</i>" : "";
            sb.Append($"""
                <tr style="vertical-align:top">
                  <td style="border-bottom:1px solid #e2e8f0"><span style="background:{color};color:#fff;border-radius:4px;padding:2px 8px;font-weight:600">{Severity.Label(a.Severity)}</span><br><span style="color:#64748b">risque {a.RiskScore}/100</span></td>
                  <td style="border-bottom:1px solid #e2e8f0"><a href="{url}" style="color:#1d4ed8;font-weight:600">{E(id)}</a>{kevBadge}<br><span style="color:#334155">{E(a.Title)}</span></td>
                  <td style="border-bottom:1px solid #e2e8f0">{E(a.TechnologyName)} <b>{E(a.TechnologyVersion)}</b>{probable}</td>
                  <td style="border-bottom:1px solid #e2e8f0">{a.CvssScore?.ToString("0.0") ?? "—"} / {(a.EpssScore is { } e ? $"{e * 100:0.#} %" : "—")}</td>
                  <td style="border-bottom:1px solid #e2e8f0">{action}</td>
                </tr>
                """);
        }
        sb.Append("</table>");
    }

    public static string Html(string kind, IReadOnlyList<Alert> alerts, IReadOnlyList<BaselineSummaryRow> baseline, string dashboardUrl,
        IReadOnlyList<Alert>? baselineAlerts = null)
    {
        baselineAlerts ??= [];
        var sb = new StringBuilder();
        sb.Append("""
            <!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"></head>
            <body style="margin:0;padding:0;background:#f1f5f9;font-family:Segoe UI,Arial,sans-serif;color:#0f172a">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:24px 0">
            <tr><td align="center">
            <table role="presentation" width="760" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #e2e8f0">
            <tr><td style="background:#0f172a;color:#ffffff;padding:20px 24px">
            """);
        sb.Append($"""<div style="font-size:20px;font-weight:600">Vigie sécurité — {(kind == "immediate" ? "alerte immédiate" : kind == "test" ? "courriel de test" : "résumé")}</div>""");
        sb.Append($"""<div style="font-size:13px;color:#cbd5e1;margin-top:4px">{DateTime.Now:yyyy-MM-dd HH:mm} · aucune action automatique n'est appliquée : information seulement</div>""");
        sb.Append("</td></tr><tr><td style=\"padding:20px 24px\">");

        if (alerts.Count > 0)
        {
            // Résumé par criticité
            sb.Append("<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin-bottom:16px\"><tr>");
            foreach (var sev in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
            {
                var c = alerts.Count(a => a.Severity == sev);
                if (c == 0) continue;
                sb.Append($"""<td style="padding:8px 14px;margin-right:8px;border-radius:6px;background:{Colors[sev]};color:#fff;font-weight:600;font-size:14px">{c} {Severity.Label(sev)}</td><td width="8"></td>""");
            }
            var kev = alerts.Count(a => a.InKev);
            if (kev > 0) sb.Append($"""<td style="padding:8px 14px;border-radius:6px;background:#7f1d1d;color:#fff;font-weight:600;font-size:14px">{kev} exploitée(s) — CISA KEV</td>""");
            sb.Append("</tr></table>");

            // Regroupement par technologie
            sb.Append("<div style=\"font-size:14px;margin-bottom:8px\"><b>Technologies touchées :</b> ");
            sb.Append(string.Join(", ", alerts.GroupBy(a => $"{a.TechnologyName} {a.TechnologyVersion}".Trim())
                .Select(g => $"{E(g.Key)} ({g.Count()})")));
            sb.Append("</div>");

            AppendAlertTable(sb, alerts);
        }

        if (baseline.Count > 0)
        {
            sb.Append("""
                <div style="margin-top:20px;padding:12px 14px;background:#f8fafc;border-left:4px solid #64748b;font-size:13px">
                <b>Inventaire initial</b> — failles déjà publiées avant la mise sous surveillance de ces technologies :
                <ul style="margin:6px 0 0 0;padding-left:18px">
                """);
            foreach (var b in baseline)
                sb.Append($"<li>{E(b.TechnologyName)} {E(b.TechnologyVersion)} : {b.Total} faille(s) dont {b.Critical} critique(s), {b.High} élevée(s)</li>");
            sb.Append("</ul></div>");

            // Détail complet de chaque faille, regroupé par technologie
            foreach (var g in baselineAlerts.GroupBy(a => $"{a.TechnologyName} {a.TechnologyVersion}".Trim()))
            {
                sb.Append($"""<div style="margin:20px 0 8px 0;font-size:15px;font-weight:600">Inventaire initial — {E(g.Key)} ({g.Count()})</div>""");
                AppendAlertTable(sb, g.ToList());
            }
        }

        sb.Append($"""
            <div style="margin-top:24px"><a href="{dashboardUrl}/nouvelles" style="background:#1d4ed8;color:#fff;padding:10px 18px;border-radius:6px;text-decoration:none;font-weight:600">Ouvrir le tableau de bord</a></div>
            </td></tr>
            <tr><td style="padding:14px 24px;background:#f8fafc;color:#64748b;font-size:11px">
            Sources : NVD (NIST), CISA KEV, MITRE CVE, OSV.dev, FIRST EPSS. Criticité = CVSS ajusté selon l'exploitation active (KEV) et la probabilité d'exploitation (EPSS).
            Ce message est généré automatiquement par la vigie ; aucun correctif n'a été appliqué.
            </td></tr></table></td></tr></table></body></html>
            """);
        return sb.ToString();
    }

    public static string Text(string kind, IReadOnlyList<Alert> alerts, IReadOnlyList<BaselineSummaryRow> baseline, string dashboardUrl,
        IReadOnlyList<Alert>? baselineAlerts = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Vigie sécurité — {(kind == "immediate" ? "ALERTE IMMÉDIATE" : "résumé")} — {DateTime.Now:yyyy-MM-dd HH:mm}");
        sb.AppendLine();
        foreach (var a in alerts) AppendAlertText(sb, a);
        foreach (var b in baseline)
            sb.AppendLine($"Inventaire initial : {b.TechnologyName} {b.TechnologyVersion} : {b.Total} faille(s) ({b.Critical} critiques)");
        if (baselineAlerts is { Count: > 0 })
        {
            sb.AppendLine();
            foreach (var g in baselineAlerts.GroupBy(a => $"{a.TechnologyName} {a.TechnologyVersion}".Trim()))
            {
                sb.AppendLine($"== Inventaire initial — {g.Key} ({g.Count()}) ==");
                foreach (var a in g) AppendAlertText(sb, a);
            }
        }
        sb.AppendLine();
        sb.AppendLine($"Tableau de bord : {dashboardUrl}");
        return sb.ToString();
    }

    private static void AppendAlertText(StringBuilder sb, Alert a)
    {
        sb.AppendLine($"[{Severity.Label(a.Severity).ToUpperInvariant()}] {a.CveId ?? a.ExternalId} — {a.TechnologyName} {a.TechnologyVersion}{(a.InKev ? " — EXPLOITÉE (KEV)" : "")}");
        sb.AppendLine($"   {a.Title}");
        sb.AppendLine($"   CVSS {a.CvssScore?.ToString("0.0") ?? "?"} ; risque {a.RiskScore}/100{(string.IsNullOrEmpty(a.FixedVersions) ? "" : $" ; corrigée en {a.FixedVersions}")}");
        sb.AppendLine($"   https://nvd.nist.gov/vuln/detail/{a.CveId ?? a.ExternalId}");
    }

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");}
