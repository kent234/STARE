import { useState, useEffect, useRef } from 'react';
import GlassButton from '../../components/ui/GlassButton';
import GraphVisualizer from '../../features/graph/GraphVisualizer';
import DataTable from '../../features/graph/DataTable';
import { detectPeopleKind } from '../../features/people/detect';
import './MainScreen.css';

function MainScreen({ onBack, onLogout }) {
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState(['[SYSTEM] Interface initialized...', '[SYSTEM] Awaiting target input.']);
  const [scanData, setScanData] = useState(null);
  const [history, setHistory] = useState([]);
  const [currentScanId, setCurrentScanId] = useState(null);
  const [viewMode, setViewMode] = useState('graph');
  // ID сканов, выбранных чекбоксами для пакетного удаления.
  const [selectedScans, setSelectedScans] = useState([]);
  const [bulkDeleting, setBulkDeleting] = useState(false);
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
        if (isMounted) {
          const scans = data || [];
          setHistory(scans);
          // Убираем из выбора ID, которых больше нет в истории.
          setSelectedScans(prev => prev.filter(id => scans.some(scan => scan.id === id)));
        }
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
      setCurrentScanId(id);
      setLogs(prev => [...prev, `[+] Loaded historical data from DB.`]);
    } catch (e) {
      setLogs(prev => [...prev, `[ERROR] ${e.message}`]);
    }
  };

  const deleteHistoricalScan = async (id, event) => {
    event.stopPropagation();
    if (!window.confirm('Delete this saved graph permanently?')) return;

    try {
      const res = await fetch(`http://localhost:8080/api/scan/delete?id=${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      if (!res.ok) throw new Error('Delete failed');
      setHistory(prev => prev.filter(item => item.id !== id));
      setSelectedScans(prev => prev.filter(selectedId => selectedId !== id));
      if (currentScanId === id) {
        setScanData(null);
        setCurrentScanId(null);
      }
      setLogs(prev => [...prev, `[DB] Deleted saved graph ${id}`]);
    } catch (err) {
      setLogs(prev => [...prev, `[ERROR] ${err.message}`]);
    }
  };

  const toggleScanSelection = (id, event) => {
    event.stopPropagation();
    setSelectedScans(prev => (
      prev.includes(id) ? prev.filter(selectedId => selectedId !== id) : [...prev, id]
    ));
  };

  const allSelected = history.length > 0 && selectedScans.length === history.length;

  const toggleSelectAll = () => {
    setSelectedScans(allSelected ? [] : history.map(scan => scan.id));
  };

  // Единая точка пакетного удаления: { ids: [...] } или { all: true }.
  const deleteScanBatch = async (payload, confirmText) => {
    if (!window.confirm(confirmText)) return;
    setBulkDeleting(true);
    try {
      const res = await fetch('http://localhost:8080/api/scans/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error('Bulk delete failed');
      const result = await res.json();
      const removed = payload.all
        ? history
        : history.filter(scan => payload.ids.includes(scan.id));

      if (payload.all) {
        setHistory([]);
        setSelectedScans([]);
        setScanData(null);
        setCurrentScanId(null);
      } else {
        setHistory(prev => prev.filter(scan => !payload.ids.includes(scan.id)));
        setSelectedScans(prev => prev.filter(id => !payload.ids.includes(id)));
        if (currentScanId && payload.ids.includes(currentScanId)) {
          setScanData(null);
          setCurrentScanId(null);
        }
      }
      setLogs(prev => [...prev, `[DB] Deleted ${result.deleted ?? removed.length} saved graph(s)`]);
    } catch (err) {
      setLogs(prev => [...prev, `[ERROR] ${err.message}`]);
    } finally {
      setBulkDeleting(false);
    }
  };

  const deleteSelectedScans = () => {
    if (selectedScans.length === 0) return;
    deleteScanBatch(
      { ids: selectedScans },
      `Delete ${selectedScans.length} selected saved graph(s) permanently?`
    );
  };

  const deleteAllScans = () => {
    if (history.length === 0) return;
    deleteScanBatch(
      { all: true },
      `Delete ALL ${history.length} saved graph(s) permanently? This cannot be undone.`
    );
  };

  const handleScan = async () => {
    if (!target.trim() || isScanning) return;
    setIsScanning(true); setScanData(null); setCurrentScanId(null);

    const peopleKind = detectPeopleKind(target);
    setLogs(prev => [
      ...prev,
      `[INIT] Connecting to backend API...`,
      peopleKind ? `[PEOPLE] Input type: ${peopleKind}` : `[SCAN] Target: ${target}`,
    ]);

    try {
      const response = await fetch(peopleKind ? 'http://localhost:8080/api/people' : 'http://localhost:8080/api/scan', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target })
      });
      if (!response.ok) throw new Error('Server error during scan');
      const data = await response.json();
      setScanData(data);
      if (data.kind === 'people') {
        setLogs(prev => [
          ...prev,
          `[+] People-OSINT complete: ${data.accounts?.length || 0} accounts`,
          `[DONE] Rendering data...`,
        ]);
      } else {
        setLogs(prev => [...prev, `[+] Scan complete in ${data.duration}`, `[DONE] Rendering data...`]);
      }
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
          <input type="text" className="terminal-input" placeholder="domain, IP, username, email, phone or profile URL..." value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleScan()} disabled={isScanning} />
        </div>
        
        <GlassButton onClick={handleScan} disabled={isScanning}>
          {isScanning ? 'SCANNING...' : '[ EXECUTE ]'}
        </GlassButton>
      </header>

      <main className="workspace">
        <section className="history-panel">
          <div className="panel-header history-header">
            <span>[ SAVED.GRAPHS ]</span>
            <div className="history-actions">
              {selectedScans.length > 0 && (
                <button
                  className="history-action"
                  title="Delete selected saved graphs"
                  onClick={deleteSelectedScans}
                  disabled={bulkDeleting}
                >
                  DEL {selectedScans.length}
                </button>
              )}
              {history.length > 0 && (
                <button
                  className="history-action"
                  title="Delete all saved graphs"
                  onClick={deleteAllScans}
                  disabled={bulkDeleting}
                >
                  DEL.ALL
                </button>
              )}
            </div>
          </div>
          <div className="history-list">
            {history.length === 0 ? (
              <div style={{ color: '#555', fontSize: '12px', textAlign: 'center', marginTop: '10px' }}>No history yet</div>
            ) : (
              <>
                <label className="history-select-all">
                  <input
                    type="checkbox"
                    className="history-check"
                    checked={allSelected}
                    onChange={toggleSelectAll}
                  />
                  <span>{allSelected ? 'clear selection' : `select all (${history.length})`}</span>
                </label>
                {history.map(scan => (
                  <div
                    key={scan.id}
                    className={`history-item${selectedScans.includes(scan.id) ? ' selected' : ''}`}
                    onClick={() => loadHistoricalScan(scan.id)}
                  >
                    <input
                      type="checkbox"
                      className="history-check"
                      title="Select for bulk delete"
                      aria-label={`Select ${scan.target}`}
                      checked={selectedScans.includes(scan.id)}
                      onChange={(e) => toggleScanSelection(scan.id, e)}
                      onClick={(e) => e.stopPropagation()}
                    />
                    <div className="history-info">
                      <div className="history-target">{scan.target}</div>
                      <div className="history-date">{new Date(scan.created_at).toLocaleTimeString()}</div>
                    </div>
                    <button
                      className="history-delete"
                      title="Delete saved graph"
                      onClick={(e) => deleteHistoricalScan(scan.id, e)}
                    >
                      [ x ]
                    </button>
                  </div>
                ))}
              </>
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