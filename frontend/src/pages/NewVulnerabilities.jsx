import { useState } from 'react'
import { api, useApi } from '../api'
import { ErrorBox, Loading, SeverityChips, SolutionSelect } from '../components/ui'
import VulnTable from '../components/VulnTable'

/** Page "Nouvelles vulnérabilités" : détectées par la vigie sur la période. */
export default function NewVulnerabilities() {
  const [days, setDays] = useState(7)
  const [severity, setSeverity] = useState('')
  const [solution, setSolution] = useState('')
  const techs = useApi(() => api.technologies(), [])
  const { data, error, loading, reload } = useApi(() => api.vulnerabilitiesNew({ days, severity, solution, pageSize: 200 }), [days, severity, solution])

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Nouvelles vulnérabilités</h1>
          <p className="muted">Failles corrélées à votre stack détectées récemment (inventaire initial inclus).</p>
        </div>
      </header>
      <div className="filters">
        <label>Période
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
            <option value={1}>24 heures</option>
            <option value={7}>7 jours</option>
            <option value={30}>30 jours</option>
            <option value={90}>90 jours</option>
          </select>
        </label>
        <SeverityChips value={severity} onChange={setSeverity} />
        <SolutionSelect techs={techs.data} value={solution} onChange={(e) => setSolution(e.target.value)} />
        <button className="btn" onClick={reload}>Actualiser</button>
      </div>
      <ErrorBox error={error} onRetry={reload} />
      <Loading show={loading} />
      {data && <>
        <p className="muted">{data.total} vulnérabilité{data.total > 1 ? 's' : ''}</p>
        <VulnTable items={data.items} showSeen />
      </>}
    </>
  )
}
