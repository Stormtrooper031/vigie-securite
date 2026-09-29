import { useState } from 'react'
import { api, fmtDateTime, useApi } from '../api'
import { ErrorBox, Loading, StatusText } from '../components/ui'

const KIND = { immediate: 'Immédiat', digest: 'Résumé', test: 'Test' }

export default function Notifications() {
  const { data, error, loading, reload } = useApi(() => api.notifications(), [])
  const [to, setTo] = useState('')
  const [msg, setMsg] = useState(null)
  const [view, setView] = useState(null)

  const act = async (fn) => {
    setMsg(null)
    try {
      const r = await fn()
      setMsg(r?.message ?? (r?.status === 'failed' ? `Échec : ${r.error}` : `Courriel ${r?.status === 'sent' ? 'envoyé' : r?.status} : ${r?.subject}`))
      reload()
    } catch (e) { setMsg(`Erreur : ${e.message}`) }
  }

  const open = async (id) => {
    try { setView(await api.notification(id)) } catch (e) { setMsg(e.message) }
  }

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Courriels</h1>
          <p className="muted">Historique des notifications. En local, les courriels arrivent dans Mailpit : <a href="http://localhost:8025" target="_blank" rel="noreferrer">localhost:8025</a>.</p>
        </div>
      </header>
      <div className="filters">
        <label>Destinataire du test <input type="email" placeholder="(par défaut NOTIFY_TO)" value={to} onChange={(e) => setTo(e.target.value)} /></label>
        <button className="btn" onClick={() => act(() => api.testEmail(to))}>Envoyer un courriel de test</button>
        <button className="btn btn-primary" onClick={() => act(() => api.sendNow())}>Envoyer le résumé maintenant</button>
      </div>
      {msg && <div className="info">{msg}</div>}
      <ErrorBox error={error} onRetry={reload} />
      <Loading show={loading} />
      {data && (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Date</th><th>Type</th><th>Sujet</th><th>Destinataires</th><th className="num">Alertes</th><th>Statut</th><th></th></tr></thead>
            <tbody>
              {data.map((n) => (
                <tr key={n.id}>
                  <td>{fmtDateTime(n.createdAt)}</td>
                  <td>{KIND[n.kind] ?? n.kind}</td>
                  <td className="wrap">{n.subject}</td>
                  <td className="small wrap">{n.recipients}</td>
                  <td className="num">{n.alertCount}</td>
                  <td><StatusText value={n.status} />{n.error && <div className="error-text small">{n.error}</div>}</td>
                  <td><button className="btn btn-small" onClick={() => open(n.id)}>Voir</button></td>
                </tr>
              ))}
              {data.length === 0 && <tr><td colSpan={7} className="muted">Aucun courriel envoyé pour l'instant.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
      {view && (
        <section className="card">
          <div className="card-head">
            <h2>{view.subject}</h2>
            <button className="btn btn-ghost" onClick={() => setView(null)}>Fermer</button>
          </div>
          {/* sandbox sans scripts : le HTML vient de notre propre modèle */}
          <iframe title="Aperçu du courriel" className="mail-preview" sandbox="" srcDoc={view.bodyHtml ?? ''} />
        </section>
      )}
    </>
  )
}
