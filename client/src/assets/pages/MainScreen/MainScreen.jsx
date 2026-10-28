import React, { useState, useEffect, useRef } from 'react';
import GlassButton from '../../components/ui/GlassButton';
import './MainScreen.css';

function MainScreen({ onBack }) {
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState(['[SYSTEM] Interface initialized...', '[SYSTEM] Awaiting target input.']);
  const logsEndRef = useRef(null);

  // Автоскролл логов вниз
  const scrollToBottom = () => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [logs]);

  const handleScan = () => {
    if (!target.trim()) {
      setLogs(prev => [...prev, '[ERROR] Target cannot be empty.']);
      return;
    }

    setIsScanning(true);
    setLogs(prev => [
      ...prev, 
      `[INIT] Starting sequence for target: ${target}`,
      `[SCAN] Resolving DNS...`,
      `[SCAN] Querying crt.sh...`
    ]);

    // Имитация работы сканера (потом заменишь на реальный fetch)
    setTimeout(() => {
      setLogs(prev => [
        ...prev, 
        `[+] Found 12 subdomains.`,
        `[SCAN] Probing ports on 192.168.1.1...`,
        `[+] Open ports: 80, 443, 3306 (MySQL).`,
        `[WARN] Outdated IIS 8.5 detected.`,
        `[DONE] Scan complete.`
      ]);
      setIsScanning(false);
    }, 3000);
  };

  return (
    <div className="main-screen">
      {/* Эффекты монитора */}
      <div className="scanlines"></div>
      <div className="crt-flicker"></div>
      <div className="vignette"></div>

      {/* ВЕРХНЯЯ ПАНЕЛЬ: Ввод */}
      <header className="control-bar">
        <button className="back-btn" onClick={onBack}>
          [ &lt; BACK ]
        </button>
        
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

      {/* ОСНОВНАЯ ЗОНА: Граф и Логи */}
      <main className="workspace">
        
        {/* Левая часть: Окно графа */}
        <section className="graph-panel">
          <div className="panel-header">[ VISUALIZER ]</div>
          <div className="graph-container">
            {!isScanning && logs.length <= 2 ? (
              <div className="placeholder-text">
                AWAITING DATA STREAM...
              </div>
            ) : (
              <div className="placeholder-text active">
                {/* Сюда позже вставим Cytoscape.js */}
                [GRAPH RENDERED HERE]
              </div>
            )}
          </div>
        </section>

        {/* Правая часть: Логи */}
        <section className="logs-panel">
          <div className="panel-header">[ SYSTEM.LOGS ]</div>
          <div className="logs-container">
            {logs.map((log, index) => (
              <div key={index} className={`log-line ${log.includes('[+]') ? 'success' : log.includes('[ERROR]') || log.includes('[WARN]') ? 'error' : ''}`}>
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