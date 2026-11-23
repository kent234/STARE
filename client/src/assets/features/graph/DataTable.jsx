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
      : (acc.existence
        ? acc.existence === 'confirmed'
        : (acc.verified || (acc.sources || []).length >= 2)))
  ));
  const registrations = data.registrations || [];
  const removed = data.removed || [];
  const collectors = data.collectors || [];
  const versions = Object.entries(data.versions || {});
  const hasAny = accounts.length || registrations.length || removed.length || collectors.length
    || (data.breaches || []).length || data.phone;

  return (
    <div className="table-wrapper">
      {!hasAny && (
        <div className="people-empty">
          No public data found for this identifier. Checked free sources: Holehe, XposedOrNot, Hudson Rock, Gravatar, GHunt (if logged in).
          Try a username/profile URL, or install OSINT CLI (Sherlock/Maigret/Blackbird).
        </div>
      )}

      {data.email && (
        <div className="table-section">
          <h3 className="table-title">EMAIL INTELLIGENCE <span>{data.email.email}</span></h3>
          <table className="terminal-table">
            <thead><tr><th>DOMAIN</th><th>FORMAT</th><th>DNS</th><th>DISPOSABLE</th><th>ROLE</th><th>FREE</th><th>MX</th></tr></thead>
            <tbody>
              <tr className="data-row">
                <td>{data.email.domain || '-'}</td>
                <td className={data.email.format ? 'safe-status' : 'risky-status'}>{data.email.format ? 'VALID' : 'INVALID'}</td>
                <td>{String(!!data.email.dns)}</td>
                <td className={data.email.disposable ? 'risky-status' : 'safe-status'}>{String(!!data.email.disposable)}</td>
                <td>{String(!!data.email.role)}</td>
                <td>{String(!!data.email.free)}</td>
                <td className="obs-summary">{(data.email.mx || []).join(', ') || '-'}</td>
              </tr>
            </tbody>
          </table>
        </div>
      )}

      <div className="table-section">
        <h3 className="table-title">
          PEOPLE-OSINT <span>
            {data.input_type}: {data.target}
            {data.scan_id ? ` · scan ${data.scan_id}` : ''}
            {data.duration_ms ? ` · ${data.duration_ms} ms` : ''}
          </span>
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
              <th>SOURCES</th><th>CONFIDENCE</th><th>EXISTENCE</th><th>VERIFICATION</th>
              <th>HTTP</th><th>SCORE</th><th>VERIFIED</th><th>MATCH</th><th>REASON</th><th>URL</th>
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
                <td className={acc.existence === 'confirmed' ? 'safe-status' : acc.existence === 'absent' ? 'risky-status' : ''}>
                  {acc.existence || 'unknown'}
                </td>
                <td className="obs-summary">
                  {acc.verification || 'none'}
                  {acc.verification_source && acc.verification_source !== 'http' ? ` · ${acc.verification_source}` : ''}
                </td>
                <td className={acc.http_status >= 400 ? 'risky-status' : ''}>
                  {acc.http_status || (acc.http_error ? 'error' : '-')}
                </td>
                <td>{acc.score ?? 0}</td>
                <td className={acc.verified ? 'safe-status' : 'risky-status'}>{acc.verified ? 'YES' : 'no'}</td>
                <td>{acc.match_score ?? 0}</td>
                <td className="obs-summary">{acc.match_reason || '-'}</td>
                <td className="clickable-cell">{acc.url || '-'}</td>
              </tr>
            ))}
            {accounts.length === 0 && (
              <tr><td colSpan="14" style={{ textAlign: 'center', color: '#666', padding: '20px' }}>No accounts above the confidence threshold</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {collectors.length > 0 && (
        <div className="table-section">
          <h3 className="table-title">
            COLLECTORS <span>{collectors.length} · kept accounts {collectors.reduce((n, c) => n + (c.kept || 0), 0)}</span>
          </h3>
          <table className="terminal-table">
            <thead><tr><th>COLLECTOR</th><th>STATUS</th><th>OBSERVATIONS</th><th>KEPT</th><th>DURATION</th><th>ERROR</th></tr></thead>
            <tbody>
              {collectors.map(item => (
                <tr key={item.name} className="data-row">
                  <td className="vuln-name">{item.name}</td>
                  <td className={item.status === 'ran' ? 'safe-status' : 'risky-status'}>{item.status}</td>
                  <td>{item.observations ?? 0}</td>
                  <td>{item.kept ?? 0}</td>
                  <td>{item.duration_ms ? `${item.duration_ms} ms` : '-'}</td>
                  <td className="obs-summary">{item.error || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {versions.length > 0 && (
            <div className="obs-summary" style={{ marginTop: '8px' }}>
              versions: {versions.map(([name, version]) => `${name} ${version}`).join(' · ')}
            </div>
          )}
        </div>
      )}

      {removed.length > 0 && (
        <div className="table-section">
          <h3 className="table-title">REMOVED PROFILES (404/410) <span>{removed.length}</span></h3>
          <table className="terminal-table">
            <thead><tr><th>PLATFORM</th><th>HANDLE</th><th>STATUS</th><th>URL</th></tr></thead>
            <tbody>
              {removed.map(item => (
                <tr key={item.id || `${item.platform}:${item.handle}`} className="data-row">
                  <td className="vuln-name">{item.platform}</td>
                  <td>{item.handle}</td>
                  <td className="risky-status">{item.http_status || 410}</td>
                  <td className="clickable-cell">{item.url || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

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

      {(data.scan_meta?.tools || data.scan_meta?.coverage) && (
        <div className="table-section">
          <h3 className="table-title">
            SCAN STATUS <span>scan {data.scan_id || '-'} · schema {data.schema_version || '-'} · {data.duration}</span>
          </h3>
          <table className="terminal-table">
            <thead><tr><th>TOOL</th><th>STATUS</th><th>DURATION</th><th>INPUT</th><th>ITEMS</th><th>NOTES</th></tr></thead>
            <tbody>
              {Object.entries(data.scan_meta?.tools || {}).map(([name, tool]) => (
                <tr key={name} className="data-row">
                  <td className="vuln-name">{name}</td>
                  <td className={tool.status === 'ran' ? 'safe-status' : 'risky-status'}>{tool.status}</td>
                  <td>{tool.duration_ms ? `${tool.duration_ms} ms` : '-'}</td>
                  <td>{tool.input ?? '-'}</td>
                  <td>{tool.items ?? '-'}</td>
                  <td className="obs-summary">
                    {tool.truncated ? 'limit hit · ' : ''}{tool.error || '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {data.scan_meta?.coverage && (
            <table className="terminal-table" style={{ marginTop: '10px' }}>
              <thead><tr><th>STAGE</th><th>ATTEMPTED</th><th>SUCCEEDED</th><th>FAILED</th><th>SKIPPED</th></tr></thead>
              <tbody>
                {Object.entries(data.scan_meta.coverage).map(([stage, cov]) => (
                  <tr key={stage} className="data-row">
                    <td className="vuln-name">{stage}</td>
                    <td>{cov.attempted ?? 0}</td>
                    <td className="safe-status">{cov.succeeded ?? 0}</td>
                    <td className={cov.failed ? 'risky-status' : ''}>{cov.failed ?? 0}</td>
                    <td>{cov.skipped ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

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

      {(data.http || []).length > 0 && (
        <div className="table-section">
          <h3 className="table-title">HTTP PROBES <span>{data.http.length}</span></h3>
          <table className="terminal-table">
            <thead><tr><th>URL</th><th>STATUS</th><th>TITLE</th><th>SERVER</th><th>TECH</th><th>TLS</th></tr></thead>
            <tbody>
              {data.http.map((probe, i) => (
                <tr key={`${probe.url}-${i}`} className="data-row">
                  <td className="clickable-cell">{probe.url || probe.input}</td>
                  <td>{probe.status_code || '-'}</td>
                  <td>{probe.title || '-'}</td>
                  <td>{probe.webserver || probe.cdn || '-'}</td>
                  <td className="obs-summary">{(probe.technologies || []).slice(0, 6).join(', ') || '-'}</td>
                  <td className="obs-summary">{probe.tls ? `${probe.tls.issuer_cn || 'cert'} · ${probe.tls.not_after || ''}` : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(data.tls || []).length > 0 && (
        <div className="table-section">
          <h3 className="table-title">TLS CERTIFICATES <span>{data.tls.length}</span></h3>
          <table className="terminal-table">
            <thead><tr><th>HOST</th><th>CN</th><th>ISSUER</th><th>SAN</th><th>NOT AFTER</th><th>STATUS</th></tr></thead>
            <tbody>
              {data.tls.map((cert, i) => (
                <tr key={`${cert.host}-${i}`} className="data-row">
                  <td>{cert.host || '-'}</td>
                  <td>{cert.subject_cn || '-'}</td>
                  <td>{cert.issuer_cn || '-'}</td>
                  <td className="obs-summary">{(cert.san || []).slice(0, 8).join(', ') || '-'}</td>
                  <td>{cert.not_after || '-'}</td>
                  <td className={cert.expired ? 'risky-status' : 'safe-status'}>{cert.expired ? 'EXPIRED' : 'VALID'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(data.endpoints || []).length > 0 && (
        <div className="table-section">
          <h3 className="table-title">ENDPOINTS (KATANA) <span>{data.endpoints.length}</span></h3>
          <div className="obs-json">{data.endpoints.slice(0, 500).join('\n')}</div>
        </div>
      )}

      {(data.cloud_buckets || []).length > 0 && (
        <div className="table-section">
          <h3 className="table-title">CLOUD BUCKETS <span>{data.cloud_buckets.length}</span></h3>
          <table className="terminal-table">
            <thead><tr><th>PROVIDER</th><th>NAME</th><th>STATUS</th><th>ACCESS</th><th>URL</th></tr></thead>
            <tbody>
              {data.cloud_buckets.map((bucket, i) => (
                <tr key={`${bucket.provider}-${bucket.name}-${i}`} className="data-row">
                  <td>{bucket.provider}</td>
                  <td>{bucket.name}</td>
                  <td>{bucket.status}</td>
                  <td className={bucket.public ? 'risky-status' : 'safe-status'}>{bucket.public ? 'PUBLIC' : 'PRIVATE'}</td>
                  <td className="clickable-cell">{bucket.url}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(data.threat_hits || []).length > 0 && (
        <div className="table-section">
          <h3 className="table-title">THREAT FEED HITS <span>{data.threat_hits.length}</span></h3>
          <table className="terminal-table">
            <thead><tr><th>SOURCE</th><th>INDICATOR</th><th>DETAIL</th></tr></thead>
            <tbody>
              {data.threat_hits.map((hit, i) => (
                <tr key={`${hit.source}-${hit.indicator}-${i}`} className="data-row">
                  <td className="obs-source">{hit.source}</td>
                  <td>{hit.indicator}</td>
                  <td className="obs-summary">{hit.detail || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

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
