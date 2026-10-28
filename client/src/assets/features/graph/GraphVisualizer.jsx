import React, { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import './GraphVisualizer.css';

function GraphVisualizer({ data }) {
  const containerRef = useRef(null);

  useEffect(() => {
    if (!data || !containerRef.current) return;

    const nodes = [];
    const edges = [];
    const addedNodes = new Set();

    // 1. Добавляем корневой домен
    nodes.push({ data: { id: data.target, label: data.target, type: 'domain' } });
    addedNodes.add(data.target);

    // 2. Добавляем IP-адреса
    data.ips?.forEach(ip => {
      if (!addedNodes.has(ip)) {
        nodes.push({ data: { id: ip, label: ip, type: 'ip' } });
        addedNodes.add(ip);
      }
      edges.push({ data: { source: data.target, target: ip } });
    });

    // 3. Добавляем Порты
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

    // 4. Добавляем Поддомены
    data.subdomains?.forEach(sub => {
      if (!addedNodes.has(sub)) {
        nodes.push({ data: { id: sub, label: sub, type: 'subdomain' } });
        addedNodes.add(sub);
      }
      edges.push({ data: { source: data.target, target: sub } });
    });

    // 5. Инициализация Cytoscape
    const cy = cytoscape({
      container: containerRef.current,
      elements: [...nodes, ...edges],
      style: [
        {
          selector: 'node',
          style: {
            'background-color': '#0a0a0a',
            'border-width': 2,
            'border-color': '#555',
            'label': 'data(label)',
            'color': '#fff',
            'font-family': 'Courier New',
            'font-size': '10px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': '40px',
            'height': '40px'
          }
        },
        { selector: 'node[type="domain"]', style: { 'border-color': '#fff', 'background-color': '#222', 'width': '60px', 'height': '60px' } },
        { selector: 'node[type="subdomain"]', style: { 'border-color': '#a0a0a0' } },
        { selector: 'node[type="ip"]', style: { 'border-color': '#00e5ff', 'color': '#00e5ff' } },
        { selector: 'node[type="risky-port"]', style: { 'border-color': '#ff003c', 'color': '#ff003c', 'background-color': '#330000' } },
        {
          selector: 'edge',
          style: {
            'width': 1,
            'line-color': '#333',
            'target-arrow-color': '#333',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier'
          }
        }
      ],
      // НАСТРОЙКИ РАСКЛАДКИ (Сделано для распределения)
      layout: {
        name: 'breadthfirst',
        animate: true,
        animationDuration: 1000,
        randomize: true,
        nodeRepulsion: 1500000,     // Огромная сила отталкивания, чтобы узлы не слипались
        idealEdgeLength: 350,      // Длина связей
        edgeElasticity: 100,       
        gravity: 0.05,             // Очень слабое притяжение к центру
        numIter: 2000,             // Больше итераций для лучшего распределения
        initialTemp: 2000,         // Высокая начальная температура (разбрасывает в начале)
        coolingFactor: 0.95,
        minTemp: 1.0
      }
    });

    return () => cy.destroy();
  }, [data]);

  return <div className="graph-container" ref={containerRef}></div>;
}

export default GraphVisualizer;