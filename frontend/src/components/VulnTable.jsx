import { Link } from 'react-router-dom'
import { fmtDate, fmtPct } from '../api'
import { CveLink, KevBadge, SeverityBadge } from './ui'

/** Tableau des vulnérabilités (liste et nouvelles). */
export default function VulnTable({ items, showSeen }) {
  if (!items?.length) return <p className="muted">Aucune vulnérabilité pour ces critères.</p>
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Criticité</th>
            <th>Identifiant</th>
            <th>Titre</th>
            <th>Technologies touchées</th>
            <th className="num">CVSS</th>
            <th className="num">EPSS</th>
            <th>Corrigée en</th>
            <th>{showSeen ? 'Détectée' : 'Publiée'}</th>
          </tr>
        </thead>
        <tbody>
          {items.map((v) => (
            <tr key={v.id}>
              <td><SeverityBadge value={v.alertSeverity ?? v.severity} />{v.riskScore != null && <div className="muted small">risque {v.riskScore}</div>}</td>
              <td><CveLink cveId={v.cveId} externalId={v.externalId} />{v.inKev && <><br /><KevBadge due={v.kevDueDate} /></>}</td>
              <td className="wrap"><Link to={`/vulnerabilites/${v.id}`}>{v.title ?? '(sans titre)'}</Link></td>
              <td className="wrap">{v.technologyNames}</td>
              <td className="num">{v.cvssScore?.toFixed(1) ?? '—'}</td>
              <td className="num">{fmtPct(v.epssScore)}</td>
              <td className="mono small">{v.fixedVersions ?? '—'}</td>
              <td>{fmtDate(showSeen ? v.firstSeenAt : v.publishedAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
