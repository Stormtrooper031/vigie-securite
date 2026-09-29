import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, fmtDateTime, useApi } from '../api'
import { CveLink, ErrorBox, KevBadge, Loading, Pager, SeverityBadge, SeverityChips } from '../components/ui'

const STATUS = { new: 'Nouvelle', acknowledged: 'Prise en compte', resolved: 'Résolue', ignored: 'Ignorée' }

export default function Alerts() {
  const [status, setStatus] = useState('new,acknowledged')
  const [severity, setSeverity] = useState('')
  const [includeBaseline, setIncludeBaseline] = useState(true)
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState([])
  const [msg, setMsg] = useState(null)
  const q = { status, severity, includeBaseline: includeBaseline ? 'true' : 'false', page, pageSize: 50 }
  const { data, error, loading, reload } = useApi(() => api.alerts(q), [JSON.stringify(q)])

  const toggle = (id) => setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]))
  const all = data?.items.map((a) => a.id) ?? []

  const apply = async (newStatus) => {
    const comment = newStatus === 'ignored' ? window.prompt('Raison (facultatif) :') ?? undefined : undefined
    try {
      const r = await api.setAlertStatus(selected, newStatus, comment)
      setMsg(`${r.updated} alerte(s) mise(s) à jour.`)
      setSelected([])
      reload()
    } catch (e) { setMsg(e.message) }
  }

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Alertes</h1>
          <p className="muted">Une alerte = une faille pertinente pour une technologie. Suivez leur traitement ici.</p>
        </div>
      </header>
      <div className="filters">
        <label>Statut
          <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1) }}>
            <option value="new,acknowledged">Ouvertes</option>
            <option value="new">Nouvelles</option>
            <option value="acknowledged">Prises en compte</option>
            <option value="resolved">Résolues</option>
            <option value="ignored">Ignorées</option>
            <option value="">Toutes</option>
          </select>
        </label>
        <SeverityChips value={severity} onChange={(v) => { setSeverity(v); setPage(1) }} />
        <label className="check"><input type="checkbox" checked={includeBaseline} onChange={(e) => setIncludeBaseline(e.target.checked)} /> Inclure l'inventaire initial</label>
      </div>

      {selected.length > 0 && (
        <div className="bulk">
          <span>{selected.length} sélectionnée(s)</span>
          <button className="btn btn-small" onClick={() => apply('acknowledged')}>Prendre en compte</button>
          <button className="btn btn-small" onClick={() => apply('resolved')}>Marquer résolue</button>
          <button className="btn btn-small" onClick={() => apply('ignored')}>Ignorer</button>
          <button className="btn btn-small" onClick={() => apply('new')}>Rouvrir</button>
        </div>
      )}
      {msg && <div className="info">{msg}</div>}
      <ErrorBox error={error} onRetry={reload} />
      <Loading show={loading} />
      {data && (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th><input type="checkbox" aria-label="Tout sélectionner" checked={all.length > 0 && all.every((id) => selected.includes(id))}
                    onChange={(e) => setSelected(e.target.checked ? all : [])} /></th>
                  <th>Criticité</th><th>Faille</th><th>Technologie</th><th>Corrigée en</th><th>Statut</th><th>Justification</th><th>Créée</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((a) => (
                  <tr key={a.id} className={selected.includes(a.id) ? 'row-selected' : ''}>
                    <td><input type="checkbox" checked={selected.includes(a.id)} onChange={() => toggle(a.id)} aria-label={`Sélectionner ${a.cveId ?? a.externalId}`} /></td>
                    <td><SeverityBadge value={a.severity} /><div className="muted small">risque {a.riskScore}</div></td>
                    <td className="wrap">
                      <CveLink cveId={a.cveId} externalId={a.externalId} /> {a.inKev && <KevBadge due={a.kevDueDate} />}
                      <div className="small wrap"><Link to={`/vulnerabilites/${a.vulnerabilityId}`}>{a.title}</Link></div>
                    </td>
                    <td>{a.technologyName} <span className="mono">{a.technologyVersion}</span>
                      {a.confidence === 'probable' && <div className="muted small">corrélation probable</div>}</td>
                    <td className="mono small">{a.fixedVersions ?? '—'}</td>
                    <td>
                      {STATUS[a.status] ?? a.status}
                      {a.kind === 'kev' && <div className="small">Escalade KEV</div>}
                      {a.isBaseline && <div className="muted small">inventaire initial</div>}
                      {a.notifiedAt && <div className="muted small">notifiée</div>}
                    </td>
                    <td className="small wrap">{a.statusComment ?? a.reason}</td>
                    <td>{fmtDateTime(a.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={data.page} pageSize={data.pageSize} total={data.total} onPage={setPage} />
        </>
      )}
    </>
  )
}
