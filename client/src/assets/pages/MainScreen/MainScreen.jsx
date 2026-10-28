import React, { useState, useEffect, useRef } from 'react';
import GlassButton from '../../components/ui/GlassButton';
import GraphVisualizer from '../../features/graph/GraphVisualizer';
import './MainScreen.css';

function MainScreen({ onBack }) {
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState(['[SYSTEM] Interface initialized...', '[SYSTEM] Awaiting target input.']);
  const [scanData, setScanData] = useState(null);
  const logsEndRef = useRef(null);

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  const handleScan = async () => {
    if (!target.trim()) return;

    setIsScanning(true);
    setScanData(null);
    setLogs(prev => [...prev, `[INIT] Connecting to backend API...`, `[SCAN] Target: ${target}`]);

    try {
      const response = await fetch('http://localhost:8080/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target })
      });

      if (!response.ok) throw new Error('Server error');

      const data = await response.json();
      
      setScanData(data);
      setLogs(prev => [
        ...prev,
        `[+] Scan complete in ${data.duration}`,
        `[+] Found ${data.subdomains?.length || 0} subdomains.`,
        `[+] Found ${Object.keys(data.ports || {}).length} hosts with open ports.`,
        `[DONE] Rendering graph...`
      ]);

    } catch (error) {
      setLogs(prev => [...prev, `[ERROR] Failed to connect: ${error.message}`]);
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
        <button className="back-btn" onClick={onBack}>[ &lt; BACK ]</button>
        <div className="input-group">
          <span className="prompt-symbol">&gt;_</span>
          <input 
            type="text" 
            className="terminal-input"
            placeholder="Enter target domain or IP..."
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleScan()}
            disabled={isScanning}
          />
        </div>
        <GlassButton onClick={handleScan} disabled={isScanning}>
          {isScanning ? 'SCANNING...' : '[ EXECUTE ]'}
        </GlassButton>
      </header>

      <main className="workspace">
        <section className="graph-panel">
          <div className="panel-header">[ VISUALIZER ]</div>
          
          {scanData ? (
             <GraphVisualizer data={scanData} />
          ) : (
            <div className="graph-container">
              <div className="placeholder-text">
                {isScanning ? 'RECEIVING DATA STREAM...' : 'AWAITING DATA STREAM...'}
              </div>
            </div>
          )}
        </section>

        <section className="logs-panel">
          <div className="panel-header">[ SYSTEM.LOGS ]</div>
          <div className="logs-container">
            {logs.map((log, index) => (
              <div key={index} className={`log-line ${log.includes('[+]') ? 'success' : log.includes('[ERROR]') ? 'error' : ''}`}>
                {log}
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </section>
      </main>
    </div>
  );
}

export default MainScreen;