import { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import {
  OBSERVATION_TYPES,
  normalizeIndicator,
  observationType,
  observationLabel,
  observationSummary,
  observationTypeLabel,
} from './observations';
import './GraphVisualizer.css';

const PrettyJson = ({ data, indent = 0 }) => {
  if (data === null) return <span className="json-null">null</span>;
  if (typeof data === 'boolean') return <span className="json-boolean">{String(data)}</span>;
  if (typeof data === 'number') return <span className="json-number">{data}</span>;
  if (typeof data === 'string') return <span className="json-string">"{data}"</span>;

  if (Array.isArray(data)) {
    if (data.length === 0) return <span className="json-bracket">[]</span>;
    return (
      <div className="json-array">
        <span className="json-bracket">[</span>
        {data.map((item, i) => (
          <div key={i} style={{ paddingLeft: `${(indent + 1) * 15}px` }}>
            <PrettyJson data={item} indent={indent + 1} />
            {i < data.length - 1 && <span className="json-comma">,</span>}
          </div>
        ))}
        <div style={{ paddingLeft: `${indent * 15}px` }} className="json-bracket">]</div>
      </div>
    );
  }

  if (typeof data === 'object') {
    const keys = Object.keys(data);
    if (keys.length === 0) return <span className="json-bracket">{'{}'}</span>;
    return (
      <div className="json-object">
        <span className="json-bracket">{'{'}</span>
        {keys.map((key, i) => (
          <div key={key} style={{ paddingLeft: `${(indent + 1) * 15}px` }}>
            <span className="json-key">"{key}"</span>
            <span className="json-colon">: </span>
            <PrettyJson data={data[key]} indent={indent + 1} />
            {i < keys.length - 1 && <span className="json-comma">,</span>}
          </div>
        ))}
        <div style={{ paddingLeft: `${indent * 15}px` }} className="json-bracket">{'}'}</div>
      </div>
    );
  }
  return null;
};

const OBS_COLORS = {
  threat: '#ff003c',
  vuln: '#ff00ff',
  reputation: '#ffd400',
  service: '#00ff9d',
  info: '#6aa9ff',
};

function GraphVisualizer({ data }) {
  const containerRef = useRef(null);
  const [tooltip, setTooltip] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    if (!data || !containerRef.current) return undefined;

    const nodes = [];
    const edges = [];
    const addedNodes = new Set();
    const matchIndex = new Map();
    let edgeSeq = 0;

    const addNode = (id, label, type, extra = {}) => {
      if (addedNodes.has(id)) return;
      nodes.push({ data: { id, label, type, ...extra } });
      addedNodes.add(id);
    };

    const link = (source, target, classes = '', label = '') => {
      edges.push({ data: { id: `e${++edgeSeq}`, source, target, label }, classes });
    };

    const registerMatch = (value, id) => {
      const key = normalizeIndicator(value);
      if (key && !matchIndex.has(key)) matchIndex.set(key, id);
    };

    addNode(data.target, data.target, 'domain');
    registerMatch(data.target, data.target);

    data.subdomains?.forEach(sub => {
      addNode(sub, sub, 'subdomain');
      registerMatch(sub, sub);
      link(data.target, sub);
      const subIPs = data.subdomain_ips?.[sub] || [];
      subIPs.forEach(ip => {
        addNode(ip, ip, 'ip');
        registerMatch(ip, ip);
        link(sub, ip);
      });
    });

    data.ips?.forEach(ip => {
      if (!addedNodes.has(ip)) {
        addNode(ip, ip, 'ip');
        registerMatch(ip, ip);
        link(data.target, ip);
      }
    });

    if (data.ports) {
      Object.entries(data.ports).forEach(([ip, ports]) => {
        ports.forEach(port => {
          const portId = `${ip}:${port}`;
          const isRisky = [22, 3306, 3389, 6379].includes(port);
          addNode(portId, `:${port}`, isRisky ? 'risky-port' : 'port');
          link(ip, portId);
        });
      });
    }

    // === Threat intelligence: target → [INTEL] → source → observation → matched infra ===
    const observations = Array.isArray(data.observations) ? data.observations : [];
    if (observations.length > 0) {
      const intelGroupId = '__intel__';
      addNode(intelGroupId, `THREAT INTEL · ${observations.length}`, 'group');
      link(data.target, intelGroupId, 'intel');

      const sourceCounts = new Map();
      observations.forEach(obs => {
        const source = obs.source || 'unknown';
        sourceCounts.set(source, (sourceCounts.get(source) || 0) + 1);
      });

      const sourceNodes = new Map();
      sourceCounts.forEach((count, source) => {
        const sourceId = `src:${source}`;
        sourceNodes.set(source, sourceId);
        addNode(sourceId, `${source} · ${count}`, 'source', { source });
        link(intelGroupId, sourceId, 'intel');
      });

      observations.forEach((obs, index) => {
        const type = observationType(obs);
        const obsId = `obs:${obs.source || 'unknown'}:${index}`;
        addNode(obsId, observationLabel(obs), type, {
          source: obs.source,
          confidence: obs.confidence_tier,
          fetchedAt: obs.fetched_at,
          payload: obs.payload || {},
        });
        link(sourceNodes.get(obs.source || 'unknown'), obsId, 'reports');

        const p = obs.payload || {};
        const matched = matchIndex.get(normalizeIndicator(p.indicator || p.hostname || ''));
        if (matched && matched !== obsId) link(obsId, matched, 'match', 'matches');
      });
    }

    let cy = null;
    try {
      cy = cytoscape({
        container: containerRef.current,
        elements: [...nodes, ...edges],
        minZoom: 0.15,
        maxZoom: 3,
        wheelSensitivity: 0.2,
        style: [
          {
            selector: 'node',
            style: {
              'background-color': '#0a0a0a',
              'border-width': 2,
              'border-color': '#555',
              'label': 'data(label)',
              'color': '#fff',
              'font-family': 'Courier New, monospace',
              'font-size': '10px',
              'text-valign': 'center',
              'text-halign': 'center',
              'text-wrap': 'ellipsis',
              'text-max-width': '130px',
              'width': '40px',
              'height': '40px',
            },
          },
          {
            selector: 'node[type="domain"]',
            style: {
              'border-color': '#ffffff',
              'border-width': 3,
              'background-color': '#1a1a1a',
              'width': '76px',
              'height': '76px',
              'font-size': '12px',
              'font-weight': 'bold',
            },
          },
          {
            selector: 'node[type="subdomain"]',
            style: { 'border-color': '#a0a0a0', 'width': '42px', 'height': '42px', 'font-size': '9px' },
          },
          {
            selector: 'node[type="ip"]',
            style: { 'border-color': '#00e5ff', 'color': '#00e5ff', 'width': '46px', 'height': '46px' },
          },
          {
            selector: 'node[type="port"], node[type="risky-port"]',
            style: {
              'shape': 'round-rectangle',
              'width': '38px',
              'height': '20px',
              'font-size': '8px',
              'background-color': '#111',
              'border-color': '#444',
              'color': '#aaa',
            },
          },
          {
            selector: 'node[type="risky-port"]',
            style: {
              'border-color': '#ff003c',
              'background-color': '#330000',
              'color': '#ff003c',
              'font-weight': 'bold',
            },
          },
          {
            selector: 'node[type="group"]',
            style: {
              'shape': 'round-rectangle',
              'width': '130px',
              'height': '30px',
              'background-color': '#211700',
              'border-color': '#ff9900',
              'border-width': 2,
              'color': '#ffcc66',
              'font-size': '9px',
              'font-weight': 'bold',
            },
          },
          {
            selector: 'node[type="source"]',
            style: {
              'shape': 'round-rectangle',
              'width': '92px',
              'height': '26px',
              'background-color': '#2a1f00',
              'border-color': '#ff9900',
              'color': '#ffcc66',
              'font-size': '8px',
            },
          },
          {
            selector: 'node.observation, node[type="threat"], node[type="vuln"], node[type="reputation"], node[type="service"], node[type="info"]',
            style: {
              'shape': 'round-rectangle',
              'width': '96px',
              'height': '26px',
              'font-size': '8px',
              'border-width': 1,
              'background-color': '#111',
            },
          },
          { selector: 'node[type="threat"]', style: { 'border-color': '#ff003c', 'background-color': '#2a0008', 'color': '#ffb3c1' } },
          { selector: 'node[type="vuln"]', style: { 'border-color': '#ff00ff', 'background-color': '#220022', 'color': '#ffb3ff' } },
          { selector: 'node[type="reputation"]', style: { 'border-color': '#ffd400', 'background-color': '#2a2400', 'color': '#ffe680' } },
          { selector: 'node[type="service"]', style: { 'border-color': '#00ff9d', 'background-color': '#002218', 'color': '#a0ffd6' } },
          { selector: 'node[type="info"]', style: { 'border-color': '#6aa9ff', 'background-color': '#0a1730', 'color': '#b3ccff' } },
          {
            selector: 'edge',
            style: {
              'width': 1,
              'line-color': '#333',
              'target-arrow-color': '#333',
              'target-arrow-shape': 'triangle',
              'arrow-scale': 0.7,
              'curve-style': 'bezier',
              'font-family': 'Courier New, monospace',
              'font-size': '6px',
              'color': '#888',
              'text-background-color': '#050505',
              'text-background-opacity': 0.85,
              'text-background-padding': '1px',
            },
          },
          { selector: 'edge.intel', style: { 'line-color': '#ff9900', 'target-arrow-color': '#ff9900', 'width': 1.5 } },
          { selector: 'edge.reports', style: { 'line-color': '#665522', 'target-arrow-color': '#665522', 'width': 0.8 } },
          { selector: 'edge.match', style: { 'line-color': '#00e5ff', 'target-arrow-color': '#00e5ff', 'line-style': 'dashed', 'width': 1 } },
        ],
        layout: {
          name: 'breadthfirst',
          directed: true,
          padding: 40,
          spacingFactor: 1.35,
          avoidOverlap: true,
          nodeDimensionsIncludeLabels: true,
          animate: false,
        },
      });
    } catch (error) {
      console.error('Cytoscape init error:', error);
    }

    if (cy) {
      cy.on('mouseover', 'node', event => {
        const node = event.target.data();
        const pos = event.target.renderedPosition();
        let text;
        if (OBSERVATION_TYPES.includes(node.type)) {
          text = `${node.source || 'source'} / ${node.type}\n${node.label}`;
        } else if (node.type === 'domain') text = `Domain: ${node.label}`;
        else if (node.type === 'subdomain') text = `Subdomain: ${node.label}`;
        else if (node.type === 'ip') text = `IP: ${node.label}`;
        else if (node.type === 'group') text = 'Threat intelligence cluster';
        else if (node.type === 'source') text = `Intel source: ${node.label}`;
        else text = `Port: ${node.label}`;
        setTooltip({ x: pos.x + 20, y: pos.y + 20, text, isRisky: node.type === 'risky-port' || node.type === 'threat' });
      });

      cy.on('mouseout', 'node', () => setTooltip(null));

      cy.on('tap', 'node', event => {
        const node = event.target.data();
        let info = { Name: node.label, Type: node.type };

        if (node.type === 'domain') {
          info.Whois = data.whois;
          info.DNS = data.dns;
          info.Technologies = data.technologies || 'Not detected';
          info.ServerHeader = data.artifacts?.server_header || 'Unknown';
          info.FaviconMD5 = data.artifacts?.favicon_md5 || 'Unknown';
          if (data.artifacts?.robots_txt?.length > 0) info.RobotsTxt = data.artifacts.robots_txt;
          info.Observations = observations.length;
          if (observations.length > 0) {
            const bySource = {};
            observations.forEach(o => { bySource[o.source] = (bySource[o.source] || 0) + 1; });
            info.IntelBySource = bySource;
          }
          if (data.errors?.length > 0) info.ScanErrors = data.errors;
        } else if (node.type === 'ip' || node.type === 'subdomain') {
          if (node.type === 'ip') {
            info.ASN = data.asn?.[node.label] || 'Unknown';
            info.OpenPorts = data.ports?.[node.label] || [];
          } else {
            info.ParentDomain = data.target;
            info.ResolvedIPs = data.subdomain_ips?.[node.label] || ['No IP resolved'];
          }
          const related = observations.filter(o => {
            const p = o.payload || {};
            return normalizeIndicator(p.indicator || p.hostname || '') === normalizeIndicator(node.label);
          });
          if (related.length > 0) info.Intel = related.map(o => `${o.source}: ${observationSummary(o)}`);
        } else if (node.type === 'port' || node.type === 'risky-port') {
          info.PortNumber = node.label;
          info.Status = 'OPEN';
          info.ServiceBanner = data.banners?.[node.id] || 'Unknown (No banner)';
          if (node.type === 'risky-port') info.Warning = 'CRITICAL RISK (Unauthorized exposure)';
        } else if (OBSERVATION_TYPES.includes(node.type)) {
          info = {
            Name: node.label,
            Source: node.source,
            Type: observationTypeLabel(node),
            Confidence: node.confidence,
            FetchedAt: node.fetchedAt,
            Payload: node.payload || {},
          };
        } else if (node.type === 'source') {
          const related = observations.filter(o => o.source === node.source);
          info.Observations = related.length;
          info.Types = [...new Set(related.map(observationTypeLabel))];
        } else if (node.type === 'group') {
          const bySource = {};
          observations.forEach(o => { bySource[o.source] = (bySource[o.source] || 0) + 1; });
          info.Observations = observations.length;
          info.BySource = bySource;
        }

        setSelectedNode(info);
      });
    }

    return function cleanup() {
      if (cy && typeof cy.destroy === 'function') cy.destroy();
    };
  }, [data]);

  return (
    <div className="graph-wrapper">
      <div className="graph-container" ref={containerRef}></div>

      <div className="graph-legend">
        <span><i style={{ background: '#1a1a1a', borderColor: '#fff' }} />Domain</span>
        <span><i style={{ background: '#0a0a0a', borderColor: '#00e5ff' }} />IP</span>
        <span><i style={{ background: '#111', borderColor: '#444' }} />Port</span>
        <span><i style={{ background: '#211700', borderColor: '#ff9900' }} />Intel source</span>
        <span><i style={{ background: '#2a0008', borderColor: OBS_COLORS.threat }} />Threat</span>
        <span><i style={{ background: '#220022', borderColor: OBS_COLORS.vuln }} />Vuln</span>
        <span><i style={{ background: '#2a2400', borderColor: OBS_COLORS.reputation }} />Reputation</span>
        <span><i style={{ background: '#0a1730', borderColor: OBS_COLORS.info }} />Info</span>
      </div>

      {tooltip && (
        <div className={`graph-tooltip ${tooltip.isRisky ? 'risky' : ''}`} style={{ left: tooltip.x, top: tooltip.y }}>
          {tooltip.text.split('\n').map((line, i) => <div key={i}>{line}</div>)}
        </div>
      )}

      {selectedNode && (
        <div className="node-details-panel">
          <div className="panel-header">
            <span>[ NODE.INFO ]</span>
            <button onClick={() => setSelectedNode(null)}>[ X ]</button>
          </div>
          <div className="panel-content">
            <div className="json-viewer">
              <PrettyJson data={selectedNode} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default GraphVisualizer;
