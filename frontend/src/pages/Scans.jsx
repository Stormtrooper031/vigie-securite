import { Fragment, useEffect, useState } from 'react'
import { api, fmtDateTime, useApi } from '../api'
import { ErrorBox, Loading, StatusText } from '../components/ui'

export default function Scans() {
  const { data, error, loading, reload } = useApi(() => api.scans(), [])
  const status = useApi(() => api.scannerStatus(), [])
  const [open, setOpen] = useState(null)
  const [msg, setMsg] = useState(null)
  const [busy, setBusy] = useState(false)

  // Rafraîchissement automatique pendant un scan
  useEffect(() => {
    const running = status.data?.running
    const t = setInterval(() => { status.reload(); if (running) reload() }, running ? 5000 : 30000)
    return () => clearInterval(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status.data?.running])

  const trigger = async () => {
    setMsg(null)
    try { await api.triggerScan(); setMsg('Scan ajouté à la file.'); setTimeout(() => { status.reload(); reload() }, 1500) }
    catch (e) { setMsg(e.message) }
  }

  const resetVulns = async () => {
    if (!window.confirm(
      'Vider les vulnérabilités, corrélations et alertes (donc « Mises à jour à faire ») ?\n\n' +
      'La stack (« Ma stack ») et l\'historique des courriels sont conservés. ' +
      'Le prochain scan refera un inventaire complet. Cette action est irréversible.'
    )) return
    setMsg(null)
    setBusy(true)
    try {
      const r = await api.resetVulnerabilities()
      setMsg(`${r.vulnerabilitiesDeleted} vulnérabilité(s) et ${r.alertsDeleted} alerte(s) supprimées. Lancez un scan pour reconstituer l'inventaire.`)
      reload()
    } catch (e) { setMsg(e.message) }
    finally { setBusy(false) }
  }

  const s = status.data
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Scans</h1>
          <p className="muted">Journal du service de surveillance (NVD, CISA KEV, MITRE, OSV, EPSS).</p>
        </div>
        <div className="actions">
          <button className="btn" onClick={() => { reload(); status.reload() }}>Actualiser</button>
          <button className="btn btn-primary" onClick={trigger}>Lancer un scan</button>
          <button className="btn btn-danger" disabled={busy} onClick={resetVulns}>Réinitialiser les vulnérabilités</button>
        </div>
      </header>
      {msg && <div className="info">{msg}</div>}

      <section className="card">
        <h2>Service de surveillance</h2>
        {status.error && <p className="error-text">Injoignable : {status.error.message}</p>}
        {s && (
          <dl className="facts">
            <dt>État</dt><dd>{s.running ? <strong>En cours — {s.currentStep}</strong> : 'En attente'}{s.queued > 0 && ` (${s.queued} en file)`}</dd>
            <dt>Planification</dt><dd>{s.schedule} — prochain : {fmtDateTime(s.nextScheduledAt)}</dd>
            <dt>Dernier résultat</dt><dd>{s.lastStatus ? <StatusText value={s.lastStatus} /> : '—'} {s.lastFinishedAt && `(${fmtDateTime(s.lastFinishedAt)})`}</dd>
            <dt>Sources</dt>
            <dd>
              {Object.entries(s.sources).filter(([k]) => k !== 'nvdApiKey').map(([k, v]) => (
                <span key={k} className={`tag ${v ? 'tag-on' : 'tag-off'}`}>{k.toUpperCase()} {v ? '✓' : '✗'}</span>
              ))}
              {!s.sources.nvdApiKey && <div className="muted small">Sans clé API NVD : scans plus lents (5 requêtes / 30 s). Voir NVD_API_KEY dans .env.</div>}
            </dd>
          </dl>
        )}
      </section>

      <ErrorBox error={error} onRetry={reload} />
      <Loading show={loading} />
      {data && (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>#</th><th>Début</th><th>Fin</th><th>Déclencheur</th><th>Statut</th><th className="num">Technos</th><th className="num">Failles lues</th><th className="num">Nouvelles</th><th className="num">Corrélations</th><th className="num">Escalades KEV</th><th></th></tr></thead>
            <tbody>
              {data.map((r) => (
                <Fragment key={r.id}>
                  <tr>
                    <td>{r.id}</td>
                    <td>{fmtDateTime(r.startedAt)}</td>
                    <td>{fmtDateTime(r.finishedAt)}</td>
                    <td>{r.triggerSource}</td>
                    <td><StatusText value={r.status} /></td>
                    <td className="num">{r.technologiesScanned}</td>
                    <td className="num">{r.vulnsFetched}</td>
                    <td className="num">{r.vulnsNew}</td>
                    <td className="num">{r.linksNew}</td>
                    <td className="num">{r.kevUpdates}</td>
                    <td><button className="btn btn-small" onClick={() => setOpen(open === r.id ? null : r.id)}>{open === r.id ? 'Masquer' : 'Journal'}</button></td>
                  </tr>
                  {open === r.id && <tr><td colSpan={11}><pre className="log">{r.log ?? '(vide)'}</pre></td></tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}
