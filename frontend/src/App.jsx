import { NavLink, Route, Routes } from 'react-router-dom'
import Dashboard from './pages/Dashboard.jsx'
import NewVulnerabilities from './pages/NewVulnerabilities.jsx'
import Vulnerabilities from './pages/Vulnerabilities.jsx'
import VulnerabilityDetail from './pages/VulnerabilityDetail.jsx'
import Updates from './pages/Updates.jsx'
import Alerts from './pages/Alerts.jsx'
import Technologies from './pages/Technologies.jsx'
import Notifications from './pages/Notifications.jsx'
import Scans from './pages/Scans.jsx'

const NAV = [
  ['/', 'Tableau de bord'],
  ['/nouvelles', 'Nouvelles vulnérabilités'],
  ['/vulnerabilites', 'Vulnérabilités'],
  ['/mises-a-jour', 'Mises à jour à faire'],
  ['/alertes', 'Alertes'],
  ['/technologies', 'Stack'],
  ['/notifications', 'Courriels'],
  ['/scans', 'Scans'],
]

export default function App() {
  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <svg viewBox="0 0 32 32" width="26" height="26" aria-hidden="true">
            <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="var(--critical)" />
            <path d="m11 16 3.5 3.5L21 13" stroke="#fff" strokeWidth="2.5" fill="none" strokeLinecap="round" />
          </svg>
          <div>
            <div className="brand-title">Vigie sécurité</div>
            <div className="brand-sub">surveillance des failles</div>
          </div>
        </div>
        <nav>
          {NAV.map(([to, label]) => (
            <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">Information seulement : aucun correctif n'est appliqué automatiquement.</div>
      </aside>
      <main className="content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/nouvelles" element={<NewVulnerabilities />} />
          <Route path="/vulnerabilites" element={<Vulnerabilities />} />
          <Route path="/vulnerabilites/:id" element={<VulnerabilityDetail />} />
          <Route path="/mises-a-jour" element={<Updates />} />
          <Route path="/alertes" element={<Alerts />} />
          <Route path="/technologies" element={<Technologies />} />
          <Route path="/notifications" element={<Notifications />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="*" element={<p>Page introuvable.</p>} />
        </Routes>
      </main>
    </div>
  )
}
