import React, { useState, useEffect, useRef } from 'react';
import GlassButton from '../../components/ui/GlassButton';
import GraphVisualizer from '../../features/graph/GraphVisualizer';
import DataTable from '../../features/graph/DataTable';
import './MainScreen.css';

function MainScreen({ onBack, onLogout }) {
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState(['[SYSTEM] Interface initialized...', '[SYSTEM] Awaiting target input.']);
  const [scanData, setScanData] = useState(null);
  const [history, setHistory] = useState([]);
  const [viewMode, setViewMode] = useState('graph');
  const logsEndRef = useRef(null);

  useEffect(() => {
    if (logsEndRef.current) logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    return undefined;
  }, [logs]);

  useEffect(() => {
    let isMounted = true;
    const fetchHistory = async () => {
      try {
        const res = await fetch('http://localhost:8080/api/scans');
        if (!res.ok) throw new Error('Backend offline');
        const data = await res.json();
        if (isMounted) setHistory(data || []);
      } catch (err) { console.log("History loading error:", err.message); }
    };
    fetchHistory();
    return () => { isMounted = false; };
  }, [scanData]);

  const loadHistoricalScan = async (id) => {
    setLogs(prev => [...prev, `[DB] Loading scan ID: ${id}`]);
    try {
      const res = await fetch(`http://localhost:8080/api/scan/get?id=${id}`);
      if (!res.ok) throw new Error('Failed to fetch scan');
      const data = await res.json();
      setScanData(data);
      setLogs(prev => [...prev, `[+] Loaded historical data from DB.`]);
    } catch (e) {
      setLogs(prev => [...prev, `[ERROR] ${e.message}`]);
    }
  };

  const handleScan = async () => {
    if (!target.trim() || isScanning) return;
    setIsScanning(true); setScanData(null);
    setLogs(prev => [...prev, `[INIT] Connecting to backend API...`, `[SCAN] Target: ${target}`]);

    try {
      const response = await fetch('http://localhost:8080/api/scan', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target })
      });
      if (!response.ok) throw new Error('Server error during scan');
      const data = await response.json();
      setScanData(data);
      setLogs(prev => [...prev, `[+] Scan complete in ${data.duration}`, `[DONE] Rendering data...`]);
    } catch (error) {
      setLogs(prev => [...prev, `[ERROR] Failed: ${error.message}`]);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="main-screen">
      <div className="scanlines"></div>
      <div className="crt-flicker"></div>
      <div className="vignette"></div>

      <header className="control-bar">
        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="back-btn" onClick={onBack}>[ &lt; BACK ]</button>
          <button className="back-btn" style={{ color: '#ff003c' }} onClick={onLogout}>[ LOGOUT ]</button>
        </div>
        
        <div className="input-group">
          <span className="prompt-symbol">&gt;_</span>
          <input type="text" className="terminal-input" placeholder="Enter target domain or IP..." value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleScan()} disabled={isScanning} />
        </div>
        
        <GlassButton onClick={handleScan} disabled={isScanning}>
          {isScanning ? 'SCANNING...' : '[ EXECUTE ]'}
        </GlassButton>
      </header>

      <main className="workspace">
        <section className="history-panel">
          <div className="panel-header">[ SAVED.GRAPHS ]</div>
          <div className="history-list">
            {history.length === 0 ? (
              <div style={{ color: '#555', fontSize: '12px', textAlign: 'center', marginTop: '10px' }}>No history yet</div>
            ) : (
              history.map(scan => (
                <div key={scan.id} className="history-item" onClick={() => loadHistoricalScan(scan.id)}>
                  <div className="history-target">{scan.target}</div>
                  <div className="history-date">{new Date(scan.created_at).toLocaleTimeString()}</div>
                </div>
              ))
            )}
          </div>
        </section>

        <section className="graph-panel">
          <div className="panel-header visualizer-header">
            <span>[ VISUALIZER ]</span>
            {scanData && (
              <div className="view-toggles">
                <button className={viewMode === 'graph' ? 'active' : ''} onClick={() => setViewMode('graph')}>[ GRAPH ]</button>
                <button className={viewMode === 'table' ? 'active' : ''} onClick={() => setViewMode('table')}>[ TABLE ]</button>
                <button className={viewMode === 'json' ? 'active' : ''} onClick={() => setViewMode('json')}>[ JSON ]</button>
              </div>
            )}
          </div>

          {scanData ? (
            <div className="visualizer-content">
              {viewMode === 'graph' && <GraphVisualizer data={scanData} />}
              {viewMode === 'table' && <DataTable data={scanData} />}
              {viewMode === 'json' && (
                <div className="json-viewer" style={{ padding: '20px', overflow: 'auto', backgroundColor: '#050505' }}>
                  <pre style={{ color: '#a0a0a0', fontFamily: 'Courier New', fontSize: '12px' }}>{JSON.stringify(scanData, null, 2)}</pre>
                </div>
              )}
            </div>
          ) : (
            <div className="graph-container">
              <div className="placeholder-text">{isScanning ? 'RECEIVING DATA STREAM...' : 'AWAITING DATA STREAM...'}</div>
            </div>
          )}
        </section>

        <section className="logs-panel">
          <div className="panel-header">[ SYSTEM.LOGS ]</div>
          <div className="logs-container">
            {logs.map((log, index) => (
              <div key={index} className={`log-line ${log.includes('[+]') ? 'success' : log.includes('[ERROR]') ? 'error' : ''}`}>{log}</div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </section>
      </main>
    </div>
  );
}
export default MainScreen;