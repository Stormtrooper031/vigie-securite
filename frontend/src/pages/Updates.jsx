import { Link } from 'react-router-dom'
import { api, useApi } from '../api'
import { ErrorBox, Loading, SeverityBadge } from '../components/ui'

/** Ce qu'il faut mettre à jour, par technologie, du plus urgent au moins urgent. */
export default function Updates() {
  const { data, error, loading, reload } = useApi(() => api.technologyUpdates(), [])
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Mises à jour à faire</h1>
          <p className="muted">
            Version minimale qui corrige toutes les failles ouvertes connues de chaque technologie.
            Après la mise à jour, modifiez la version dans « Ma stack » : les alertes corrigées se ferment automatiquement.
          </p>
        </div>
        <div className="actions"><button className="btn" onClick={reload}>Actualiser</button></div>
      </header>
      <ErrorBox error={error} onRetry={reload} />
      <Loading show={loading} />
      {data && (data.length === 0
        ? <div className="card"><p>Aucune mise à jour requise pour les alertes ouvertes.</p></div>
        : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Urgence</th><th>Technologie</th><th>Version actuelle</th><th>Mettre à jour vers</th>
                  <th className="num">Alertes</th><th className="num">Critiques</th><th className="num">KEV</th><th>Principales failles</th>
                </tr>
              </thead>
              <tbody>
                {data.map((u) => (
                  <tr key={u.technologyId}>
                    <td><SeverityBadge value={u.maxSeverity} /></td>
                    <td><Link to={`/vulnerabilites?technologyId=${u.technologyId}`}>{u.name}</Link> <span className="muted small">{u.type}</span></td>
                    <td className="mono">{u.currentVersion || '—'}</td>
                    <td className="mono strong">
                      {u.recommendedVersion ? `≥ ${u.recommendedVersion}` : '—'}
                      {u.withoutFix > 0 && <div className="muted small">{u.withoutFix} faille(s) sans correctif publié</div>}
                    </td>
                    <td className="num">{u.openAlerts}</td>
                    <td className="num">{u.critical}</td>
                    <td className="num">{u.kev > 0 ? <span className="kev">{u.kev}</span> : 0}</td>
                    <td className="mono small wrap">{u.topCves.join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
    </>
  )
}
