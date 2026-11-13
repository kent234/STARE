import { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import fcose from 'cytoscape-fcose';
import {
  OBSERVATION_TYPES,
  normalizeIndicator,
  observationType,
  observationLabel,
  observationSummary,
  observationTypeLabel,
} from './observations';
import './GraphVisualizer.css';

cytoscape.use(fcose);

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

const BIG_GRAPH = 3000;
const INITIAL_NEIGHBORS = 120;
const EXPAND_NEIGHBORS = 250;

const NODE_FILTERS = [
  ['domain', 'Domain'],
  ['subdomain', 'Subdomain'],
  ['ip', 'IP'],
  ['port', 'Port'],
  ['group', 'Intel group'],
  ['source', 'Source'],
  ['threat', 'Threat'],
  ['vuln', 'Vuln finding'],
  ['reputation', 'Reputation'],
  ['service', 'Service'],
  ['info', 'Info'],
  ['vulnerability', 'Nuclei vuln'],
  ['vuln-group', 'Vuln group'],
  ['actor', 'Actor'],
  ['account', 'Account'],
  ['registration', 'Registration'],
  ['breach', 'Breach'],
  ['phone', 'Phone'],
];

const confidenceRank = (value) => {
  const v = String(value || '').toLowerCase();
  if (v === 'high' || v === 'critical') return 3;
  if (v === 'medium') return 2;
  return 1;
};

function GraphVisualizer({ data }) {
  const containerRef = useRef(null);
  const minimapRef = useRef(null);
  const cyRef = useRef(null);
  const revealedRef = useRef(new Set());
  const filtersRef = useRef({ hiddenTypes: [], minConfidence: 'medium', showUnverified: false });
  const applyVisibilityRef = useRef(null);
  const focusRef = useRef(null);

  const [tooltip, setTooltip] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [showFilters, setShowFilters] = useState(false);
  const [hiddenTypes, setHiddenTypes] = useState([]);
  const [minConfidence, setMinConfidence] = useState('medium');
  const [showUnverified, setShowUnverified] = useState(false);
  const [search, setSearch] = useState('');
  const [rendererName, setRendererName] = useState('canvas');
  const [stats, setStats] = useState(null);

  useEffect(() => {
    filtersRef.current = { hiddenTypes, minConfidence, showUnverified };
    applyVisibilityRef.current?.();
  }, [hiddenTypes, minConfidence, showUnverified]);

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

    const isPeople = data.kind === 'people';
    let rootId = data.target;

    if (isPeople) {
      const actor = data.actor;
      rootId = actor?.id || `actor:${String(data.target).toLowerCase()}`;
      addNode(rootId, actor?.label || data.target, 'actor', {
        confidence: actor?.confidence_tier || 'low',
        accounts: actor?.accounts || [],
      });

      (data.accounts || []).forEach(acc => {
        const id = acc.id || `account:${acc.platform}:${acc.handle}`;
        const label = acc.name ? `${acc.name} · ${acc.platform}` : `${acc.platform}: ${acc.handle}`;
        addNode(id, label, 'account', {
          platform: acc.platform,
          handle: acc.handle,
          url: acc.url,
          name: acc.name,
          bio: acc.bio,
          avatar: acc.avatar,
          links: acc.links || [],
          confidence: acc.confidence_tier,
          verified: !!acc.verified,
          score: acc.score || 0,
          matchScore: acc.match_score || 0,
          matchReason: acc.match_reason || '',
          sources: acc.sources || [],
          multiSource: !!acc.multi_source,
        });
        link(rootId, id, 'observed_as', 'observed_as');
      });

      (data.registrations || []).forEach((reg, i) => {
        const id = `reg:${reg.platform || 'unknown'}:${i}`;
        addNode(id, `registration: ${reg.platform}`, 'registration', {
          platform: reg.platform,
          email: reg.email,
          source: reg.source,
          confidence: 'medium',
        });
        link(rootId, id, 'registered_on', 'registered_on');
      });

      (data.breaches || []).forEach((breach, i) => {
        const id = `breach:${breach.name || 'unknown'}:${i}`;
        addNode(id, breach.name || 'breach', 'breach', {
          email: breach.email,
          date: breach.date,
          dataClasses: breach.data_classes || [],
          confidence: 'high',
        });
        link(rootId, id, 'leaked_in', 'leaked_in');
      });

      if (data.phone) {
        const id = `phone:${data.phone.indicator || 'unknown'}`;
        addNode(id, data.phone.e164 || data.phone.indicator, 'phone', {
          country: data.phone.country,
          countryCode: data.phone.country_code,
          carrier: data.phone.carrier,
          valid: data.phone.valid,
          confidence: 'medium',
        });
        link(rootId, id, 'has_phone', 'has_phone');
      }
    } else {
      addNode(data.target, data.target, 'domain');
      registerMatch(data.target, data.target);
    }

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
    const observations = !isPeople && Array.isArray(data.observations) ? data.observations : [];
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

    // === Уязвимости Nuclei: target → [VULNERABILITIES] → finding → matched infra ===
    const vulnerabilities = !isPeople && Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
    if (vulnerabilities.length > 0) {
      const vulnGroupId = '__vulns__';
      addNode(vulnGroupId, `VULNERABILITIES · ${vulnerabilities.length}`, 'vuln-group');
      link(data.target, vulnGroupId, 'vuln');

      vulnerabilities.forEach((v, index) => {
        const severity = (v.severity || 'unknown').toLowerCase();
        const vulnId = `vuln:${v.template_id || 'unknown'}:${index}`;
        addNode(vulnId, `${severity.toUpperCase()} · ${v.name || v.template_id || 'finding'}`, 'vulnerability', {
          severity,
          templateId: v.template_id,
          matchedAt: v.matched_at,
        });
        link(vulnGroupId, vulnId, 'vuln');

        const matched = matchIndex.get(normalizeIndicator(v.matched_at || ''));
        if (matched) link(vulnId, matched, 'match', 'affects');
      });
    }

    const big = nodes.length + edges.length > BIG_GRAPH;
    // По умолчанию canvas (стабильность). WebGL — только явно (VITE_GRAPH_RENDERER=webgl)
    // или через auto; в headless/software WebGL-preview оказался медленнее canvas.
    const pref = import.meta.env.VITE_GRAPH_RENDERER || 'canvas';
    const wantWebGL = pref === 'webgl' || (pref === 'auto' && big);

    const style = [
      {
        selector: 'node',
        style: {
          'background-color': '#0a0a0a',
          'border-width': 2,
          'border-color': '#555',
          label: 'data(label)',
          color: '#fff',
          'font-family': 'Courier New, monospace',
          'font-size': '10px',
          'text-valign': 'center',
          'text-halign': 'center',
          'text-wrap': 'ellipsis',
          'text-max-width': '130px',
          width: '40px',
          height: '40px',
        },
      },
      {
        selector: 'node[type="domain"]',
        style: {
          'border-color': '#ffffff',
          'border-width': 3,
          'background-color': '#1a1a1a',
          width: '76px',
          height: '76px',
          'font-size': '12px',
          'font-weight': 'bold',
        },
      },
      { selector: 'node[type="subdomain"]', style: { 'border-color': '#a0a0a0', width: '42px', height: '42px', 'font-size': '9px' } },
      { selector: 'node[type="ip"]', style: { 'border-color': '#00e5ff', color: '#00e5ff', width: '46px', height: '46px' } },
      {
        selector: 'node[type="port"], node[type="risky-port"]',
        style: {
          shape: 'round-rectangle',
          width: '38px',
          height: '20px',
          'font-size': '8px',
          'background-color': '#111',
          'border-color': '#444',
          color: '#aaa',
        },
      },
      { selector: 'node[type="risky-port"]', style: { 'border-color': '#ff003c', 'background-color': '#330000', color: '#ff003c', 'font-weight': 'bold' } },
      {
        selector: 'node[type="group"]',
        style: {
          shape: 'round-rectangle',
          width: '130px',
          height: '30px',
          'background-color': '#211700',
          'border-color': '#ff9900',
          'border-width': 2,
          color: '#ffcc66',
          'font-size': '9px',
          'font-weight': 'bold',
        },
      },
      {
        selector: 'node[type="source"]',
        style: {
          shape: 'round-rectangle',
          width: '92px',
          height: '26px',
          'background-color': '#2a1f00',
          'border-color': '#ff9900',
          color: '#ffcc66',
          'font-size': '8px',
        },
      },
      {
        selector: 'node.observation, node[type="threat"], node[type="vuln"], node[type="reputation"], node[type="service"], node[type="info"]',
        style: {
          shape: 'round-rectangle',
          width: '96px',
          height: '26px',
          'font-size': '8px',
          'border-width': 1,
          'background-color': '#111',
        },
      },
      { selector: 'node[type="threat"]', style: { 'border-color': '#ff003c', 'background-color': '#2a0008', color: '#ffb3c1' } },
      { selector: 'node[type="vuln"]', style: { 'border-color': '#ff00ff', 'background-color': '#220022', color: '#ffb3ff' } },
      { selector: 'node[type="reputation"]', style: { 'border-color': '#ffd400', 'background-color': '#2a2400', color: '#ffe680' } },
      { selector: 'node[type="service"]', style: { 'border-color': '#00ff9d', 'background-color': '#002218', color: '#a0ffd6' } },
      { selector: 'node[type="info"]', style: { 'border-color': '#6aa9ff', 'background-color': '#0a1730', color: '#b3ccff' } },
      {
        selector: 'node[type="vulnerability"]',
        style: {
          shape: 'round-rectangle',
          width: '110px',
          height: '26px',
          'font-size': '8px',
          'border-color': '#ff00ff',
          'background-color': '#220022',
          color: '#ffb3ff',
        },
      },
      {
        selector: 'node[type="vuln-group"]',
        style: {
          shape: 'round-rectangle',
          width: '140px',
          height: '30px',
          'background-color': '#1e001e',
          'border-color': '#ff00ff',
          'border-width': 2,
          color: '#ffb3ff',
          'font-size': '9px',
          'font-weight': 'bold',
        },
      },
      {
        selector: 'node[type="actor"]',
        style: {
          shape: 'ellipse',
          width: '90px',
          height: '90px',
          'background-color': '#2a1f00',
          'border-color': '#ffcc66',
          'border-width': 3,
          color: '#ffe680',
          'font-size': '11px',
          'font-weight': 'bold',
        },
      },
      {
        selector: 'node[type="account"]',
        style: {
          shape: 'round-rectangle',
          width: '110px',
          height: '26px',
          'background-color': '#001a22',
          'border-color': '#00e5ff',
          'border-style': 'dashed',
          color: '#a0f0ff',
          'font-size': '8px',
        },
      },
      { selector: 'node[type="account"][verified]', style: { 'border-style': 'solid' } },
      {
        selector: 'node[type="registration"]',
        style: {
          shape: 'round-rectangle',
          width: '110px',
          height: '24px',
          'background-color': '#111',
          'border-color': '#888',
          'border-style': 'dashed',
          color: '#bbb',
          'font-size': '8px',
        },
      },
      {
        selector: 'node[type="breach"]',
        style: {
          shape: 'round-rectangle',
          width: '110px',
          height: '26px',
          'background-color': '#2a0008',
          'border-color': '#ff003c',
          color: '#ffb3c1',
          'font-size': '8px',
        },
      },
      {
        selector: 'node[type="phone"]',
        style: {
          shape: 'round-rectangle',
          width: '110px',
          height: '26px',
          'background-color': '#002218',
          'border-color': '#00ff9d',
          color: '#a0ffd6',
          'font-size': '8px',
        },
      },
      {
        selector: 'edge',
        style: {
          width: 1,
          'line-color': '#333',
          'target-arrow-color': '#333',
          'target-arrow-shape': 'triangle',
          'arrow-scale': 0.7,
          'curve-style': 'bezier',
          'font-family': 'Courier New, monospace',
          'font-size': '6px',
          color: '#888',
          'text-background-color': '#050505',
          'text-background-opacity': 0.85,
          'text-background-padding': '1px',
        },
      },
      { selector: 'edge.intel', style: { 'line-color': '#ff9900', 'target-arrow-color': '#ff9900', width: 1.5 } },
      { selector: 'edge.vuln', style: { 'line-color': '#ff00ff', 'target-arrow-color': '#ff00ff', width: 1.2 } },
      { selector: 'edge.reports', style: { 'line-color': '#665522', 'target-arrow-color': '#665522', width: 0.8 } },
      { selector: 'edge.match', style: { 'line-color': '#00e5ff', 'target-arrow-color': '#00e5ff', 'line-style': 'dashed', width: 1 } },
      { selector: 'edge.observed_as', style: { 'line-color': '#00e5ff', 'target-arrow-color': '#00e5ff', width: 1.2 } },
      { selector: 'edge.registered_on', style: { 'line-color': '#888', 'target-arrow-color': '#888', 'line-style': 'dashed', width: 0.8 } },
      { selector: 'edge.leaked_in', style: { 'line-color': '#ff003c', 'target-arrow-color': '#ff003c', width: 1.2 } },
      { selector: 'edge.has_phone', style: { 'line-color': '#00ff9d', 'target-arrow-color': '#00ff9d', width: 1.2 } },
    ];

    // Для больших графов убираем подписи и рёберные лейблы — это главная цена растеризации.
    if (big) {
      style.push({ selector: 'node', style: { 'text-opacity': 0 } });
      style.push({ selector: 'node[type="domain"]', style: { 'text-opacity': 1 } });
      style.push({
        selector: 'node[type="port"], node[type="risky-port"], node[type="threat"], node[type="vuln"], node[type="reputation"], node[type="service"], node[type="info"], node[type="vulnerability"], node[type="source"]',
        style: { 'text-opacity': 0 },
      });
      style.push({ selector: 'edge', style: { 'font-size': '0px' } });
    }

    const createCy = (webgl) => cytoscape({
      container: containerRef.current,
      elements: [...nodes, ...edges],
      minZoom: 0.15,
      maxZoom: 3,
      wheelSensitivity: 0.2,
      pixelRatio: big ? 1 : undefined,
      hideEdgesOnViewport: big,
      textureOnViewport: big,
      motionBlur: false,
      motionBlurOpacity: 0,
      webgl,
      webglBgColor: [5, 5, 5],
      style,
      layout: {
        name: 'fcose',
        quality: big ? 'draft' : 'default',
        numIter: big ? 600 : 2500,
        // fcose 2.2.0: quality "draft" требует spectral-координат (randomize=true).
        randomize: big,
        animate: false,
        fit: true,
        padding: 40,
        nodeSeparation: 75,
        idealEdgeLength: 100,
        nodeRepulsion: 4500,
        gravity: 0.25,
      },
    });

    let cy = null;
    let initMs;
    const initStart = performance.now();
    try {
      cy = createCy(wantWebGL);
      if (wantWebGL && !cy.renderer()?.webgl) throw new Error('webgl renderer unavailable');
    } catch (error) {
      console.warn('Graph renderer fallback to canvas:', error.message);
      try {
        cy = createCy(false);
      } catch (fallbackError) {
        console.error('Cytoscape init error:', fallbackError);
      }
    }
    initMs = performance.now() - initStart;

    if (!cy) return undefined;
    cyRef.current = cy;

    const actualRenderer = cy.renderer()?.webgl ? 'webgl' : 'canvas';
    setRendererName(actualRenderer);

    const targetId = rootId;
    const targetNode = cy.getElementById(targetId);
    const revealed = new Set([targetId]);
    if (targetNode.nonempty()) {
      targetNode.neighborhood().nodes().slice(0, INITIAL_NEIGHBORS).forEach(n => revealed.add(n.id()));
    }
    revealedRef.current = revealed;

    const applyVisibility = () => {
      const { hiddenTypes: hidden, minConfidence: minConf, showUnverified: allowUnverified } = filtersRef.current;
      const showAllNodes = revealedRef.current.has('*');
      const visible = new Set();
      const start = performance.now();
      cy.batch(() => {
        cy.nodes().forEach(node => {
          const d = node.data();
          let vis = showAllNodes || revealedRef.current.has(d.id);
          if (vis && hidden.includes(d.type)) vis = false;
          if (vis && minConf !== 'all') {
            const conf = OBSERVATION_TYPES.includes(d.type) ? d.confidence : (d.severity || d.confidence);
            if (conf !== undefined && confidenceRank(conf) < confidenceRank(minConf)) vis = false;
          }
          if (vis && d.type === 'account' && !allowUnverified) {
            const strong = data.input_type === 'profile_url'
              ? (d.matchScore || 0) >= 50
              : (!!d.verified || (d.sources || []).length >= 2 || (d.score || 0) >= 70);
            if (!strong) vis = false;
          }
          node.style('display', vis ? 'element' : 'none');
          if (vis) visible.add(d.id);
        });
        cy.edges().forEach(edge => {
          const vis = visible.has(edge.source().id()) && visible.has(edge.target().id());
          edge.style('display', vis ? 'element' : 'none');
        });
      });
      const elapsed = performance.now() - start;
      if (import.meta.env.DEV && window.__graphMetrics) {
        window.__graphMetrics.lastFilterMs = Math.round(elapsed);
      }
    };
    applyVisibilityRef.current = applyVisibility;
    applyVisibility();

    const focusNode = (query) => {
      const term = String(query || '').trim().toLowerCase();
      if (!term) return;
      const node = cy.nodes().filter(n => {
        const label = String(n.data('label') || '').toLowerCase();
        return label.includes(term) || n.id().toLowerCase().includes(term);
      }).first();
      if (node.empty()) return;
      revealedRef.current.add(node.id());
      node.neighborhood().nodes().slice(0, EXPAND_NEIGHBORS).forEach(n => revealedRef.current.add(n.id()));
      applyVisibility();
      cy.animate({ center: { eles: node }, zoom: 1.2 }, { duration: 250 });
      setSelectedNode({ Name: node.data('label'), Type: node.data('type'), Matched: node.id() });
    };
    focusRef.current = focusNode;

    const tooltipFor = (node) => {
      if (node.type === 'actor') return `Actor: ${node.label}`;
      if (node.type === 'account') return `Account: ${node.label}\n${(node.sources || []).join(', ')} · score ${node.score || 0}${node.verified ? ' · verified' : ''}`;
      if (node.type === 'registration') return `Email registration: ${node.platform}`;
      if (node.type === 'breach') return `Breach: ${node.label}`;
      if (node.type === 'phone') return `Phone: ${node.label}`;
      if (node.type === 'vulnerability') return `Vulnerability (${node.severity})\n${node.label}`;
      if (node.type === 'vuln-group') return 'Nuclei vulnerabilities cluster';
      if (OBSERVATION_TYPES.includes(node.type)) return `${node.source || 'source'} / ${node.type}\n${node.label}`;
      if (node.type === 'domain') return `Domain: ${node.label}`;
      if (node.type === 'subdomain') return `Subdomain: ${node.label}`;
      if (node.type === 'ip') return `IP: ${node.label}`;
      if (node.type === 'group') return 'Threat intelligence cluster';
      if (node.type === 'source') return `Intel source: ${node.label}`;
      return `Port: ${node.label}`;
    };

    cy.on('mouseover', 'node', event => {
      const node = event.target.data();
      const pos = event.target.renderedPosition();
      setTooltip({
        x: pos.x + 20,
        y: pos.y + 20,
        text: tooltipFor(node),
        isRisky: node.type === 'risky-port' || node.type === 'threat' || node.type === 'vulnerability',
      });
    });
    cy.on('mouseout', 'node', () => setTooltip(null));

    cy.on('tap', 'node', event => {
      const node = event.target.data();

      // Progressive disclosure: раскрываем соседей выбранного узла.
      if (!revealedRef.current.has('*')) {
        revealedRef.current.add(node.id);
        event.target.neighborhood().nodes().slice(0, EXPAND_NEIGHBORS).forEach(n => revealedRef.current.add(n.id()));
        applyVisibility();
      }

      let info = { Name: node.label, Type: node.type };

      if (node.type === 'actor') {
        info = {
          Name: node.label,
          Type: 'Actor',
          Confidence: node.confidence,
          Accounts: (node.accounts || []).length,
          Input: data.input_type,
        };
      } else if (node.type === 'account') {
        info = {
          Name: node.label,
          Type: 'Account',
          Platform: node.platform,
          Handle: node.handle,
          DisplayName: node.name,
          Bio: node.bio,
          Avatar: node.avatar,
          Links: node.links,
          URL: node.url,
          Sources: node.sources,
          Confidence: node.confidence,
          Verified: node.verified,
          Score: node.score,
          MatchScore: node.matchScore,
          MatchReason: node.matchReason,
          MultiSource: node.multiSource,
        };
      } else if (node.type === 'registration') {
        info = {
          Name: node.label,
          Type: 'Email Registration',
          Platform: node.platform,
          Email: node.email,
          Source: node.source,
          Confidence: node.confidence,
        };
      } else if (node.type === 'breach') {
        info = {
          Name: node.label,
          Type: 'Breach',
          Email: node.email,
          Date: node.date,
          DataClasses: node.dataClasses,
          Confidence: node.confidence,
        };
      } else if (node.type === 'phone') {
        info = {
          Name: node.label,
          Type: 'Phone',
          Country: node.country,
          CountryCode: node.countryCode,
          Carrier: node.carrier,
          Valid: node.valid,
          Confidence: node.confidence,
        };
      } else if (node.type === 'domain') {
        info.Whois = data.whois;
        info.DNS = data.dns;
        info.Technologies = data.technologies || 'Not detected';
        info.ServerHeader = data.artifacts?.server_header || 'Unknown';
        info.FaviconMD5 = data.artifacts?.favicon_md5 || 'Unknown';
        if (data.artifacts?.robots_txt?.length > 0) info.RobotsTxt = data.artifacts.robots_txt;
        info.Observations = observations.length;
        info.Vulnerabilities = vulnerabilities.length;
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
        const relatedVulns = vulnerabilities.filter(v => normalizeIndicator(v.matched_at || '') === normalizeIndicator(node.label));
        if (relatedVulns.length > 0) info.Vulnerabilities = relatedVulns.map(v => `${v.severity}: ${v.name}`);
      } else if (node.type === 'port' || node.type === 'risky-port') {
        info.PortNumber = node.label;
        info.Status = 'OPEN';
        info.ServiceBanner = data.banners?.[node.id] || 'Unknown (No banner)';
        if (node.type === 'risky-port') info.Warning = 'CRITICAL RISK (Unauthorized exposure)';
      } else if (node.type === 'vulnerability') {
        info = {
          Name: node.label,
          Type: 'Vulnerability',
          Severity: node.severity,
          TemplateID: node.templateId,
          MatchedAt: node.matchedAt,
        };
      } else if (node.type === 'vuln-group') {
        info = { Name: node.label, Type: 'Vulnerabilities', Findings: vulnerabilities.length };
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

    // === Мини-карта ===
    let minimapRaf = null;
    const drawMinimap = () => {
      const canvas = minimapRef.current;
      if (!canvas || cy.destroyed()) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      const w = canvas.width;
      const h = canvas.height;
      ctx.clearRect(0, 0, w, h);
      ctx.fillStyle = 'rgba(5,5,5,0.9)';
      ctx.fillRect(0, 0, w, h);

      const visible = cy.nodes(':visible');
      if (visible.length === 0) return;
      const bb = visible.boundingBox({ includeLabels: false });
      const sx = (w - 8) / Math.max(bb.w, 1);
      const sy = (h - 8) / Math.max(bb.h, 1);
      const scale = Math.min(sx, sy);
      const ox = 4 - bb.x1 * scale;
      const oy = 4 - bb.y1 * scale;

      ctx.fillStyle = 'rgba(0,229,255,0.55)';
      const step = visible.length > 1500 ? Math.ceil(visible.length / 1500) : 1;
      visible.forEach((n, i) => {
        if (i % step !== 0) return;
        const p = n.position();
        ctx.fillRect(p.x * scale + ox, p.y * scale + oy, 1.5, 1.5);
      });

      const ext = cy.extent();
      ctx.strokeStyle = 'rgba(255,255,255,0.8)';
      ctx.lineWidth = 1;
      ctx.strokeRect(
        ext.x1 * scale + ox,
        ext.y1 * scale + oy,
        Math.max((ext.x2 - ext.x1) * scale, 2),
        Math.max((ext.y2 - ext.y1) * scale, 2)
      );
    };
    const scheduleMinimap = () => {
      if (minimapRaf) return;
      minimapRaf = requestAnimationFrame(() => {
        minimapRaf = null;
        drawMinimap();
      });
    };
    cy.on('render viewport', scheduleMinimap);
    scheduleMinimap();

    if (import.meta.env.DEV) {
      window.__cy = cy;
      const canvasEl = containerRef.current?.querySelector('canvas');
      const metrics = {
        initMs: Math.round(initMs),
        nodes: cy.nodes().length,
        edges: cy.edges().length,
        domNodes: document.querySelectorAll('*').length,
        canvas: canvasEl ? { width: canvasEl.width, height: canvasEl.height } : null,
        renderer: actualRenderer,
        fpsHistory: [],
        lastFilterMs: 0,
      };
      window.__graphMetrics = metrics;
      window.__graphShowAll = () => {
        revealedRef.current.add('*');
        applyVisibility();
      };
      window.__graphFilterBench = (predicate) => {
        const start = performance.now();
        cy.batch(() => {
          cy.nodes().forEach(node => {
            node.style('display', predicate(node.data()) ? 'element' : 'none');
          });
        });
        return performance.now() - start;
      };
      window.__benchDrag = (duration = 2000) => new Promise(resolve => {
        const start = performance.now();
        let frames = 0;
        function step(t) {
          frames++;
          const dt = t - start;
          cy.viewport({
            pan: { x: dt * 0.2, y: dt * 0.05 },
            zoom: 1 + 0.2 * Math.sin(dt / 400),
          });
          if (dt < duration) requestAnimationFrame(step);
          else resolve(frames / (dt / 1000));
        }
        requestAnimationFrame(step);
      });

      let frames = 0;
      let last = performance.now();
      const loop = (now) => {
        frames++;
        if (now - last >= 1000) {
          metrics.fpsHistory.push(frames);
          if (metrics.fpsHistory.length > 10) metrics.fpsHistory.shift();
          frames = 0;
          last = now;
        }
        window.__graphRaf = requestAnimationFrame(loop);
      };
      window.__graphRaf = requestAnimationFrame(loop);
      setStats({
        nodes: metrics.nodes,
        edges: metrics.edges,
        initMs: metrics.initMs,
        renderer: actualRenderer,
      });
    }

    return function cleanup() {
      if (window.__graphRaf) cancelAnimationFrame(window.__graphRaf);
      if (minimapRaf) cancelAnimationFrame(minimapRaf);
      if (cy && typeof cy.destroy === 'function') cy.destroy();
      cyRef.current = null;
      applyVisibilityRef.current = null;
      focusRef.current = null;
    };
  }, [data]);

  const toggleType = (type) => {
    setHiddenTypes(prev => (prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]));
  };

  return (
    <div className="graph-wrapper">
      <div className="graph-container" ref={containerRef}></div>

      <div className="graph-toolbar">
        <input
          className="graph-search"
          type="search"
          placeholder="Search node (domain, IP, handle...)"
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') focusRef.current?.(search); }}
        />
        <button className={`graph-toolbar-btn ${showFilters ? 'active' : ''}`} onClick={() => setShowFilters(v => !v)}>
          [ FILTERS ]
        </button>
        <span className={`renderer-badge ${rendererName}`}>{rendererName.toUpperCase()}</span>
        {stats && import.meta.env.DEV && (
          <span className="graph-stats">
            {stats.nodes}n/{stats.edges}e · layout {stats.initMs}ms
          </span>
        )}
      </div>

      {showFilters && (
        <div className="filters-panel">
          <div className="filters-title">NODE TYPES</div>
          <div className="filters-grid">
            {NODE_FILTERS.map(([type, label]) => (
              <label key={type} className="filter-item">
                <input
                  type="checkbox"
                  checked={!hiddenTypes.includes(type)}
                  onChange={() => toggleType(type)}
                />
                {label}
              </label>
            ))}
          </div>
          <div className="filters-title">CONFIDENCE</div>
          <div className="filters-grid">
            {['all', 'high', 'medium', 'low'].map(level => (
              <label key={level} className="filter-item">
                <input
                  type="radio"
                  name="confidence"
                  checked={minConfidence === level}
                  onChange={() => setMinConfidence(level)}
                />
                {level}
              </label>
            ))}
          </div>
          <label className="filter-item" style={{ marginTop: '8px' }}>
            <input
              type="checkbox"
              checked={showUnverified}
              onChange={() => setShowUnverified(v => !v)}
            />
            show unverified / single-source accounts
          </label>
          <button className="graph-toolbar-btn" onClick={() => { revealedRef.current.add('*'); applyVisibilityRef.current?.(); }}>
            [ SHOW ALL ]
          </button>
        </div>
      )}

      <div className="graph-legend">
        <span><i style={{ background: '#1a1a1a', borderColor: '#fff' }} />Domain</span>
        <span><i style={{ background: '#0a0a0a', borderColor: '#00e5ff' }} />IP</span>
        <span><i style={{ background: '#111', borderColor: '#444' }} />Port</span>
        <span><i style={{ background: '#211700', borderColor: '#ff9900' }} />Intel source</span>
        <span><i style={{ background: '#2a0008', borderColor: OBS_COLORS.threat }} />Threat</span>
        <span><i style={{ background: '#2a2400', borderColor: OBS_COLORS.reputation }} />Reputation</span>
        <span><i style={{ background: '#220022', borderColor: OBS_COLORS.vuln }} />Vulnerability</span>
        <span><i style={{ background: '#0a1730', borderColor: OBS_COLORS.info }} />Info</span>
      </div>

      <canvas className="graph-minimap" ref={minimapRef} width="180" height="120" aria-label="Graph minimap" />

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
