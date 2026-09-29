import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, fmtDateTime, useApi } from '../api'
import { ErrorBox, Kpi, Loading, SEVERITY_LABEL, StatusText } from '../components/ui'
import { SeverityBars, TimelineChart, TopTechnologiesChart } from '../components/charts'

const FREQ = { immediate: 'immédiat', hourly: 'chaque heure', daily: 'quotidien', weekly: 'hebdomadaire' }

export default function Dashboard() {
  const [days, setDays] = useState(30)
  const { data, error, loading, reload } = useApi(() => api.dashboard(days), [days])
  const [msg, setMsg] = useState(null)

  const scanNow = async () => {
    setMsg(null)
    try {
      await api.triggerScan()
      setMsg('Scan demandé : suivez-le dans la page Scans.')
    } catch (e) { setMsg(e.message) }
  }

  const s = data
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Tableau de bord</h1>
          <p className="muted">Vue globale des vulnérabilités qui touchent votre stack.</p>
        </div>
        <div className="actions">
          <button className="btn" onClick={reload}>Actualiser</button>
          <button className="btn btn-primary" onClick={scanNow}>Lancer un scan</button>
        </div>
      </header>
      {msg && <div className="info">{msg}</div>}
      <ErrorBox error={error} onRetry={reload} />
      <Loading show={loading && !s} />

      {s && (
        <>
          <section className="kpis">
            <Kpi label="Alertes critiques ouvertes" value={s.openBySeverity?.CRITICAL ?? 0} tone={s.openBySeverity?.CRITICAL ? 'critical' : undefined} />
            <Kpi label="Exploitées activement (KEV)" value={s.kevOpen} tone={s.kevOpen ? 'critical' : undefined} hint="failles au catalogue CISA KEV" />
            <Kpi label="Alertes ouvertes" value={s.alertsOpen} hint={`${s.openBySeverity?.HIGH ?? 0} élevées`} />
            <Kpi label="Nouvelles (7 jours)" value={s.newLast7Days} hint="hors inventaire initial" />
            <Kpi label="Vulnérabilités corrélées" value={s.vulnerabilitiesTotal} />
            <Kpi label="Technologies surveillées" value={s.technologiesActive} />
          </section>

          <section className="grid-2">
            <div className="card">
              <h2>Alertes ouvertes par criticité</h2>
              <SeverityBars bySeverity={s.openBySeverity} />
            </div>
            <div className="card">
              <h2>État de la vigie</h2>
              <dl className="facts">
                <dt>Dernier scan</dt>
                <dd>
                  {s.lastScan ? <>
                    {fmtDateTime(s.lastScan.startedAt)} — <StatusText value={s.lastScan.status} />
                    <br /><span className="muted">{s.lastScan.technologiesScanned} technologies, {s.lastScan.linksNew} nouvelles corrélations</span>
                  </> : 'aucun'}
                </dd>
                <dt>Courriels</dt>
                <dd>
                  {s.settings.enabled ? <>
                    {FREQ[s.settings.frequency] ?? s.settings.frequency}, seuil « {SEVERITY_LABEL[s.settings.minSeverity] ?? s.settings.minSeverity} », immédiat dès « {SEVERITY_LABEL[s.settings.immediateSeverity] ?? 'jamais'} »
                    <br /><span className="muted">à {s.settings.to} via {s.settings.smtpHost}</span>
                  </> : 'désactivés'}
                </dd>
                <dt>Prochain résumé</dt>
                <dd>{fmtDateTime(s.settings.nextDigestAt)}</dd>
                <dt>Dernier courriel</dt>
                <dd>{s.lastNotification ? <>{fmtDateTime(s.lastNotification.createdAt)} — {s.lastNotification.subject}</> : 'aucun'}</dd>
              </dl>
              <p><Link to="/mises-a-jour">Voir les mises à jour à faire →</Link></p>
            </div>
          </section>

          <section className="card">
            <div className="card-head">
              <h2>Nouvelles alertes par jour</h2>
              <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Période">
                <option value={14}>14 jours</option>
                <option value={30}>30 jours</option>
                <option value={90}>90 jours</option>
              </select>
            </div>
            <TimelineChart timeline={s.timeline} />
          </section>

          <section className="card">
            <h2>Technologies les plus exposées</h2>
            <TopTechnologiesChart items={s.topTechnologies} />
          </section>
        </>
      )}
    </>
  )
}
