import React, { useState } from 'react';
import {
  observationType,
  observationTypeLabel,
  observationSummary,
} from './observations';
import './DataTable.css';

function PeopleTable({ data }) {
  const [showLow, setShowLow] = useState(false);
  const allAccounts = data.accounts || [];
  const accounts = allAccounts.filter(acc => (
    showLow || (data.input_type === 'profile_url'
      ? (acc.match_score || 0) >= 50
      : (acc.verified || (acc.sources || []).length >= 2 || (acc.score || 0) >= 70))
  ));
  const registrations = data.registrations || [];
  const hasAny = accounts.length || registrations.length || (data.breaches || []).length || data.phone;

  return (
    <div className="table-wrapper">
      {!hasAny && (
        <div className="people-empty">
          No public data found for this identifier. Checked free sources: Holehe, XposedOrNot, Hudson Rock, Gravatar, GHunt (if logged in).
          Try a username/profile URL, or install OSINT CLI (Sherlock/Maigret/Blackbird).
        </div>
      )}

      <div className="table-section">
        <h3 className="table-title">
          PEOPLE-OSINT <span>{data.input_type}: {data.target}</span>
        </h3>
        <div className="table-hint" style={{ textAlign: 'left' }}>
          <label className="filter-item">
            <input type="checkbox" checked={showLow} onChange={() => setShowLow(v => !v)} />
            show low-confidence / unverified
          </label>
        </div>
        <table className="terminal-table">
          <thead>
            <tr>
              <th>PLATFORM</th><th>HANDLE</th><th>NAME</th><th>BIO</th>
              <th>SOURCES</th><th>CONFIDENCE</th><th>SCORE</th><th>VERIFIED</th><th>MATCH</th><th>REASON</th><th>URL</th>
            </tr>
          </thead>
          <tbody>
            {accounts.map(acc => (
              <tr key={acc.id} className="data-row">
                <td className="vuln-name">{acc.platform}</td>
                <td>{acc.handle}</td>
                <td>{acc.name || '-'}</td>
                <td className="obs-summary">{acc.bio || '-'}</td>
                <td className="obs-source">{(acc.sources || []).join(', ')}{acc.multi_source ? ' · multi_source' : ''}</td>
                <td><span className={`confidence confidence-${acc.confidence_tier}`}>{acc.confidence_tier}</span></td>
                <td>{acc.score ?? 0}</td>
                <td className={acc.verified ? 'safe-status' : 'risky-status'}>{acc.verified ? 'YES' : 'no'}</td>
                <td>{acc.match_score ?? 0}</td>
                <td className="obs-summary">{acc.match_reason || '-'}</td>
                <td className="clickable-cell">{acc.url || '-'}</td>
              </tr>
            ))}
            {accounts.length === 0 && (
              <tr><td colSpan="11" style={{ textAlign: 'center', color: '#666', padding: '20px' }}>No accounts above the confidence threshold</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {registrations.length > 0 && (
        <div className="table-section">
          <h3 className="table-title">EMAIL REGISTRATIONS (HOLEHE) <span>{registrations.length} sites</span></h3>
          <table className="terminal-table">
            <thead><tr><th>PLATFORM</th><th>EMAIL</th><th>SOURCE</th><th>CONFIDENCE</th></tr></thead>
            <tbody>
              {registrations.map((reg, i) => (
                <tr key={`${reg.platform}-${i}`} className="data-row">
                  <td className="vuln-name">{reg.platform}</td>
                  <td>{reg.email}</td>
                  <td className="obs-source">{reg.source}</td>
                  <td><span className={`confidence confidence-${reg.confidence_tier}`}>{reg.confidence_tier}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(data.breaches || []).length > 0 && (
        <div className="table-section">
          <h3 className="table-title">BREACHES <span>{data.breaches.length}</span></h3>
          <table className="terminal-table">
            <thead><tr><th>NAME</th><th>DATE</th><th>DATA CLASSES</th><th>EMAIL</th></tr></thead>
            <tbody>
              {data.breaches.map((b, i) => (
                <tr key={`${b.name}-${i}`} className="data-row">
                  <td className="vuln-name">{b.name}</td>
                  <td>{b.date || '-'}</td>
                  <td className="obs-summary">{(b.data_classes || []).join(', ') || '-'}</td>
                  <td>{b.email || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data.phone && (
        <div className="table-section">
          <h3 className="table-title">PHONE <span>basic attributes</span></h3>
          <table className="terminal-table">
            <thead><tr><th>INDICATOR</th><th>E164</th><th>COUNTRY</th><th>CODE</th><th>CARRIER</th><th>VALID</th></tr></thead>
            <tbody>
              <tr className="data-row">
                <td>{data.phone.indicator}</td>
                <td>{data.phone.e164 || '-'}</td>
                <td>{data.phone.country || '-'}</td>
                <td>{data.phone.country_code || '-'}</td>
                <td>{data.phone.carrier || '-'}</td>
                <td className={data.phone.valid ? 'safe-status' : 'risky-status'}>{String(data.phone.valid)}</td>
              </tr>
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function DataTable({ data }) {
  const [expandedRow, setExpandedRow] = useState(null);

  if (!data) return null;
  if (data.kind === 'people') return <PeopleTable data={data} />;

  const rows = [];

  if (data.ports) {
    Object.entries(data.ports).forEach(([ip, ports]) => {
      const asn = data.asn?.[ip] || 'Unknown';

      let subdomains = [];
      if (data.subdomain_ips) {
        Object.entries(data.subdomain_ips).forEach(([sub, subIPs]) => {
          if (subIPs.includes(ip)) subdomains.push(sub);
        });
      }
      if (ip === data.ips?.[0] || subdomains.length === 0) {
        if (ip !== data.target) subdomains.unshift(data.target);
      }

      ports.forEach(port => {
        const portId = `${ip}:${port}`;
        const banner = data.banners?.[portId] || 'No banner detected';
        const isRisky = [22, 3306, 3389, 6379].includes(port);
        const tech = data.technologies?.slice(0, 3).join(', ') || '-';

        rows.push({
          id: portId,
          subdomain: subdomains.join(', '),
          ip,
          port,
          banner,
          asn: asn.replace('ASN: ', '').replace(' | Country:', '/'),
          risky: isRisky,
          tech: (port === 80 || port === 443 || port === 8080) ? tech : '-',
        });
      });
    });
  }

  const observations = Array.isArray(data.observations) ? data.observations : [];
  const obsRows = observations.map((obs, i) => ({
    id: `obs:${obs.source || 'unknown'}:${i}`,
    source: obs.source || 'unknown',
    type: observationType(obs),
    typeLabel: observationTypeLabel(obs),
    indicator: obs.payload?.indicator || obs.payload?.url || obs.payload?.id || '-',
    summary: observationSummary(obs),
    confidence: obs.confidence_tier || '-',
    fetchedAt: obs.fetched_at,
    payload: obs.payload || {},
  }));

  const vulnerabilities = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
  const vulnRows = vulnerabilities.map((v, i) => ({
    id: `vuln:${v.template_id || 'unknown'}:${i}`,
    severity: (v.severity || 'unknown').toLowerCase(),
    name: v.name || v.template_id || 'Unknown finding',
    templateId: v.template_id || '-',
    matchedAt: v.matched_at || '-',
  }));

  const toggleRow = (id) => {
    setExpandedRow(prev => (prev === id ? null : id));
  };

  return (
    <div className="table-wrapper">
      <div className="table-hint">💡 Click on any row to expand details</div>

      <div className="table-section">
        <h3 className="table-title">
          INFRASTRUCTURE <span>{rows.length} rows</span>
        </h3>
        <table className="terminal-table">
          <thead>
            <tr>
              <th>SUBDOMAIN</th>
              <th>IP</th>
              <th>PORT</th>
              <th>SERVICE / TECH</th>
              <th>ASN</th>
              <th>STATUS</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const isExpanded = expandedRow === row.id;

              return (
                <React.Fragment key={row.id}>
                  <tr
                    className={`data-row ${row.risky ? 'risky-row' : ''} ${isExpanded ? 'active-row' : ''}`}
                    onClick={() => toggleRow(row.id)}
                  >
                    <td>{row.subdomain || '-'}</td>
                    <td className="clickable-cell">{row.ip}</td>
                    <td className={row.risky ? 'risky-port' : ''}>{row.port}</td>
                    <td>
                      {row.banner !== 'No banner detected' && <div style={{ color: '#888', fontSize: '11px' }}>{row.banner}</div>}
                      {row.tech !== '-' && <div style={{ color: '#00e5ff' }}>{row.tech}</div>}
                      {row.banner === 'No banner detected' && row.tech === '-' && '-'}
                    </td>
                    <td>{row.asn}</td>
                    <td className={row.risky ? 'risky-status' : 'safe-status'}>
                      {row.risky ? '⚠ CRITICAL' : 'OPEN'}
                    </td>
                  </tr>

                  {isExpanded && (
                    <tr className="expanded-row">
                      <td colSpan="6">
                        <div className="expanded-content">
                          <div className="terminal-output">
                            <p><span className="prompt">&gt;</span> <strong>Target:</strong> {row.subdomain}</p>
                            <p><span className="prompt">&gt;</span> <strong>IP Address:</strong> {row.ip}</p>
                            <p><span className="prompt">&gt;</span> <strong>Port:</strong> {row.port} ({row.risky ? 'UNAUTHORIZED EXPOSURE' : 'STANDARD'})</p>
                            <p><span className="prompt">&gt;</span> <strong>Service Banner:</strong> {row.banner}</p>
                            <p><span className="prompt">&gt;</span> <strong>Technologies:</strong> {row.tech}</p>
                            <p><span className="prompt">&gt;</span> <strong>ASN Info:</strong> {row.asn}</p>
                            {row.risky && (
                              <p className="warning-text">
                                <span className="prompt" style={{ color: '#ff003c' }}>!</span>
                                WARNING: This port is exposed and poses a critical security risk.
                              </p>
                            )}
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', color: '#666', padding: '20px' }}>
                  No open ports found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="table-section">
        <h3 className="table-title">
          THREAT INTELLIGENCE <span>{obsRows.length} observations</span>
        </h3>
        <table className="terminal-table">
          <thead>
            <tr>
              <th>SOURCE</th>
              <th>TYPE</th>
              <th>INDICATOR</th>
              <th>DETAILS</th>
              <th>CONFIDENCE</th>
            </tr>
          </thead>
          <tbody>
            {obsRows.map((row) => {
              const isExpanded = expandedRow === row.id;

              return (
                <React.Fragment key={row.id}>
                  <tr
                    className={`data-row ${isExpanded ? 'active-row' : ''}`}
                    onClick={() => toggleRow(row.id)}
                  >
                    <td className="obs-source">{row.source}</td>
                    <td>
                      <span className={`obs-badge ${row.type}`}>{row.typeLabel}</span>
                    </td>
                    <td className="clickable-cell">{row.indicator}</td>
                    <td className="obs-summary">{row.summary || '-'}</td>
                    <td>
                      <span className={`confidence confidence-${row.confidence}`}>{row.confidence}</span>
                    </td>
                  </tr>

                  {isExpanded && (
                    <tr className="expanded-row">
                      <td colSpan="5">
                        <div className="expanded-content">
                          <div className="terminal-output">
                            <p><span className="prompt">&gt;</span> <strong>Source:</strong> {row.source}</p>
                            <p><span className="prompt">&gt;</span> <strong>Type:</strong> {row.typeLabel}</p>
                            <p><span className="prompt">&gt;</span> <strong>Indicator:</strong> {row.indicator}</p>
                            <p><span className="prompt">&gt;</span> <strong>Confidence:</strong> {row.confidence}</p>
                            <p><span className="prompt">&gt;</span> <strong>Fetched At:</strong> {row.fetchedAt || 'unknown'}</p>
                          </div>
                          <pre className="obs-json">{JSON.stringify(row.payload, null, 2)}</pre>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
            {obsRows.length === 0 && (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', color: '#666', padding: '20px' }}>
                  No threat intelligence observations
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="table-section">
        <h3 className="table-title">
          VULNERABILITIES (NUCLEI) <span>{vulnRows.length} findings</span>
        </h3>
        <table className="terminal-table">
          <thead>
            <tr>
              <th>SEVERITY</th>
              <th>NAME</th>
              <th>TEMPLATE</th>
              <th>MATCHED AT</th>
            </tr>
          </thead>
          <tbody>
            {vulnRows.map((row) => {
              const isExpanded = expandedRow === row.id;

              return (
                <React.Fragment key={row.id}>
                  <tr
                    className={`data-row ${isExpanded ? 'active-row' : ''}`}
                    onClick={() => toggleRow(row.id)}
                  >
                    <td>
                      <span className={`sev-badge sev-${row.severity}`}>{row.severity}</span>
                    </td>
                    <td className="vuln-name">{row.name}</td>
                    <td className="obs-summary">{row.templateId}</td>
                    <td className="clickable-cell">{row.matchedAt}</td>
                  </tr>

                  {isExpanded && (
                    <tr className="expanded-row">
                      <td colSpan="4">
                        <div className="expanded-content">
                          <div className="terminal-output">
                            <p><span className="prompt">&gt;</span> <strong>Severity:</strong> {row.severity}</p>
                            <p><span className="prompt">&gt;</span> <strong>Name:</strong> {row.name}</p>
                            <p><span className="prompt">&gt;</span> <strong>Template:</strong> {row.templateId}</p>
                            <p><span className="prompt">&gt;</span> <strong>Matched At:</strong> {row.matchedAt}</p>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
            {vulnRows.length === 0 && (
              <tr>
                <td colSpan="4" style={{ textAlign: 'center', color: '#666', padding: '20px' }}>
                  No Nuclei findings (nuclei is optional / not installed)
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default DataTable;
