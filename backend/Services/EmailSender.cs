using System.Net;
using System.Net.Mail;
using System.Net.Mime;
using Microsoft.Extensions.Options;
using Vigie.Api.Models;

namespace Vigie.Api.Services;

/// <summary>Envoi SMTP (System.Net.Mail). Compatible Mailpit/MailHog, relais interne, Office 365 (STARTTLS 587).</summary>
public sealed class EmailSender(IOptionsMonitor<SmtpOptions> options, ILogger<EmailSender> logger)
{
    public async Task SendAsync(IEnumerable<string> to, string subject, string html, string text, CancellationToken ct = default)
    {
        var o = options.CurrentValue;
        using var msg = new MailMessage { From = new MailAddress(o.From, "Vigie Sécurité"), Subject = subject };
        foreach (var r in to) msg.To.Add(r);
        if (msg.To.Count == 0) throw new InvalidOperationException("Aucun destinataire (NOTIFY_TO).");

        msg.Body = text;
        msg.IsBodyHtml = false;
        msg.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(html, System.Text.Encoding.UTF8, MediaTypeNames.Text.Html));
        msg.BodyEncoding = System.Text.Encoding.UTF8;
        msg.SubjectEncoding = System.Text.Encoding.UTF8;
        msg.Headers.Add("X-Vigie-Securite", "1");

        using var client = new SmtpClient(o.Host, o.Port)
        {
            EnableSsl = o.EnableSsl,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            Timeout = 30_000
        };
        if (!string.IsNullOrEmpty(o.User))
            client.Credentials = new NetworkCredential(o.User, o.Password);

        await client.SendMailAsync(msg, ct);
        logger.LogInformation("Courriel envoyé à {To} via {Host}:{Port} : {Subject}", string.Join(",", to), o.Host, o.Port, subject);
    }
}
