import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import './GraphVisualizer.css';

// Компонент для красивого вывода JSON (с цветами)
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

function GraphVisualizer({ data }) {
  const containerRef = useRef(null);
  const [tooltip, setTooltip] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    if (!data || !containerRef.current) return;

    const nodes = [];
    const edges = [];
    const addedNodes = new Set();

    nodes.push({ data: { id: data.target, label: data.target, type: 'domain' } });
    addedNodes.add(data.target);

    data.subdomains?.forEach(sub => {
      if (!addedNodes.has(sub)) {
        nodes.push({ data: { id: sub, label: sub, type: 'subdomain' } });
        addedNodes.add(sub);
        edges.push({ data: { source: data.target, target: sub } });
      }
      const subIPs = data.subdomain_ips?.[sub] || [];
      subIPs.forEach(ip => {
        if (!addedNodes.has(ip)) {
          nodes.push({ data: { id: ip, label: ip, type: 'ip' } });
          addedNodes.add(ip);
        }
        edges.push({ data: { source: sub, target: ip } }); 
      });
    });

    data.ips?.forEach(ip => {
      if (!addedNodes.has(ip)) {
        nodes.push({ data: { id: ip, label: ip, type: 'ip' } });
        addedNodes.add(ip);
        edges.push({ data: { source: data.target, target: ip } });
      }
    });

    if (data.ports) {
      Object.entries(data.ports).forEach(([ip, ports]) => {
        ports.forEach(port => {
          const portId = `${ip}:${port}`;
          if (!addedNodes.has(portId)) {
            const isRisky = [22, 3306, 3389, 6379].includes(port);
            nodes.push({ data: { id: portId, label: `:${port}`, type: isRisky ? 'risky-port' : 'port' } });
            addedNodes.add(portId);
          }
          edges.push({ data: { source: ip, target: portId } });
        });
      });
    }

    let cy = null;
    try {
      cy = cytoscape({
        container: containerRef.current,
        elements: [...nodes, ...edges],
        style: [
          { selector: 'node', style: { 'background-color': '#0a0a0a', 'border-width': 2, 'border-color': '#555', 'label': 'data(label)', 'color': '#fff', 'font-family': 'Courier New', 'font-size': '10px', 'text-valign': 'center', 'text-halign': 'center', 'width': '40px', 'height': '40px' } },
          { selector: 'node[type="domain"]', style: { 'border-color': '#fff', 'background-color': '#222', 'width': '60px', 'height': '60px' } },
          { selector: 'node[type="subdomain"]', style: { 'border-color': '#a0a0a0' } },
          { selector: 'node[type="ip"]', style: { 'border-color': '#00e5ff', 'color': '#00e5ff' } },
          { selector: 'node[type="risky-port"]', style: { 'border-color': '#ff003c', 'color': '#ff003c', 'background-color': '#330000' } },
          { selector: 'edge', style: { 'width': 1, 'line-color': '#333', 'target-arrow-color': '#333', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier' } }
        ],
        layout: { name: 'cose', animate: true, nodeRepulsion: 1500000, idealEdgeLength: 150, gravity: 0.1 }
      });
    } catch (error) {
      console.error(error);
    }

    if (cy) {
      cy.on('mouseover', 'node', (event) => {
        const node = event.target.data();
        const pos = event.target.renderedPosition();
        let text = '';
        if (node.type === 'domain') text = `Domain: ${node.label}`;
        else if (node.type === 'subdomain') text = `Subdomain: ${node.label}`;
        else if (node.type === 'ip') text = `IP: ${node.label}`;
        else text = `Port: ${node.label}`;
        setTooltip({ x: pos.x + 20, y: pos.y + 20, text, isRisky: node.type === 'risky-port' });
      });

      cy.on('mouseout', 'node', () => setTooltip(null));

      cy.on('tap', 'node', (event) => {
        const node = event.target.data();
        let info = { Name: node.label, Type: node.type };

        if (node.type === 'domain') {
          info.Whois = data.whois;
          info.DNS = data.dns;
          info.Technologies = data.technologies || "Not detected";
          info.ServerHeader = data.artifacts?.server_header || "Unknown";
          info.FaviconMD5 = data.artifacts?.favicon_md5 || "Unknown";
          if (data.artifacts?.robots_txt?.length > 0) info.RobotsTxt = data.artifacts.robots_txt;
          if (data.errors?.length > 0) info.ScanErrors = data.errors;
        } 
        else if (node.type === 'ip') {
          info.ASN = data.asn?.[node.label] || 'Unknown';
          info.OpenPorts = data.ports?.[node.label] || [];
        } 
        else if (node.type === 'subdomain') {
           info.ParentDomain = data.target;
           info.ResolvedIPs = data.subdomain_ips?.[node.label] || ["No IP resolved"]; 
        }
        else if (node.type === 'port' || node.type === 'risky-port') {
           info.PortNumber = node.label;
           info.Status = "OPEN";
           
           if (data.banners && data.banners[node.id]) {
             info.ServiceBanner = data.banners[node.id];
           } else {
             info.ServiceBanner = "Unknown (No banner)";
           }

           if (node.type === 'risky-port') info.Warning = "CRITICAL RISK (Unauthorized exposure)";
        }
        
        setSelectedNode(info);
      });
    }

    return () => { if (cy) cy.destroy(); };
  }, [data]);

  return (
    <div className="graph-wrapper">
      <div className="graph-container" ref={containerRef}></div>
      
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