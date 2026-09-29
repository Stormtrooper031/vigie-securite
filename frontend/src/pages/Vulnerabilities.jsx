import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, useApi } from '../api'
import { ErrorBox, Loading, Pager, SeverityChips, SolutionSelect } from '../components/ui'
import VulnTable from '../components/VulnTable'

const EMPTY = { severity: '', technologyId: '', solution: '', from: '', to: '', kev: false, search: '', sort: 'risk' }

/** Vue globale avec filtres : criticité, technologie, solution, dates de publication, KEV, recherche. */
export default function Vulnerabilities() {
  const [params] = useSearchParams()
  const [f, setF] = useState({ ...EMPTY, technologyId: params.get('technologyId') ?? '', solution: params.get('solution') ?? '' })
  const [page, setPage] = useState(1)
  const techs = useApi(() => api.technologies(), [])
  const query = { ...f, kev: f.kev ? 'true' : '', page, pageSize: 50 }
  const { data, error, loading, reload } = useApi(() => api.vulnerabilities(query), [JSON.stringify(query)])

  const set = (k) => (e) => { setPage(1); setF({ ...f, [k]: e?.target ? (e.target.type === 'checkbox' ? e.target.checked : e.target.value) : e }) }

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Vulnérabilités</h1>
          <p className="muted">Toutes les failles corrélées à au moins une technologie de votre stack.</p>
        </div>
        <div className="actions">
          <a className="btn" href={api.exportUrl({ ...f, kev: f.kev ? 'true' : '' })}>Exporter CSV</a>
        </div>
      </header>

      <div className="filters">
        <SeverityChips value={f.severity} onChange={set('severity')} />
        <label>Technologie
          <select value={f.technologyId} onChange={set('technologyId')}>
            <option value="">Toutes</option>
            {techs.data?.map((t) => <option key={t.id} value={t.id}>{t.name} {t.version}</option>)}
          </select>
        </label>
        <SolutionSelect techs={techs.data} value={f.solution} onChange={set('solution')} />
        <label>Publiée du <input type="date" value={f.from} onChange={set('from')} /></label>
        <label>au <input type="date" value={f.to} onChange={set('to')} /></label>
        <label className="check"><input type="checkbox" checked={f.kev} onChange={set('kev')} /> Exploitées (KEV)</label>
        <label>Recherche <input type="search" placeholder="CVE, mot-clé…" value={f.search} onChange={set('search')} /></label>
        <label>Tri
          <select value={f.sort} onChange={set('sort')}>
            <option value="risk">Risque</option>
            <option value="cvss">CVSS</option>
            <option value="published">Publication</option>
            <option value="seen">Détection</option>
          </select>
        </label>
        <button className="btn btn-ghost" onClick={() => { setF(EMPTY); setPage(1) }}>Réinitialiser</button>
      </div>

      <ErrorBox error={error} onRetry={reload} />
      <Loading show={loading} />
      {data && <>
        <VulnTable items={data.items} />
        <Pager page={data.page} pageSize={data.pageSize} total={data.total} onPage={setPage} />
      </>}
    </>
  )
}
