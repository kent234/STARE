import React, { useState } from 'react';
import './DataTable.css';

function DataTable({ data }) {
  const [expandedRow, setExpandedRow] = useState(null);

  if (!data) return null;

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
          tech: (port === 80 || port === 443 || port === 8080) ? tech : '-'
        });
      });
    });
  }

  const toggleRow = (id) => {
    setExpandedRow(prev => prev === id ? null : id);
  };

  return (
    <div className="table-wrapper">
      <div className="table-hint">💡 Click on any row to expand details</div>
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
                    {row.banner !== 'No banner detected' && <div style={{color: '#888', fontSize: '11px'}}>{row.banner}</div>}
                    {row.tech !== '-' && <div style={{color: '#00e5ff'}}>{row.tech}</div>}
                    {row.banner === 'No banner detected' && row.tech === '-' && '-'}
                  </td>
                  <td>{row.asn}</td>
                  <td className={row.risky ? 'risky-status' : 'safe-status'}>
                    {row.risky ? '⚠ CRITICAL' : 'OPEN'}
                  </td>
                </tr>

                {/* РАСКРЫВАЮЩИЙСЯ БЛОК */}
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
                              <span className="prompt" style={{color: '#ff003c'}}>!</span> 
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
  );
}

export default DataTable;