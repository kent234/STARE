import { useState, useEffect } from 'react';
import LoginScreen from './assets/pages/LoginScreen/LoginScreen';
import StartScreen from './assets/pages/StartScreen/StartScreen';
import MainScreen from './assets/pages/MainScreen/MainScreen';
import GraphVisualizer from './assets/features/graph/GraphVisualizer';
import { buildBenchData } from './assets/features/graph/benchData';
import './App.css';

const BOOT_MESSAGES = [
  "S.T.A.R.E OS v1.0.4 (Kernel build 2026.10.29)",
  "Copyright (c) 2026 S.T.A.R.E Team. All rights reserved.",
  "----------------------------------------------------------------",
  "[OK] Initializing system core...",
  "[OK] Mounting virtual file system...",
  "[OK] Loading networking modules (TCP/IP stack)...",
  "[OK] Starting cryptographic services...",
  "[WAIT] Establishing secure tunnel to INTEL-DB...",
  "[OK] Decrypting user session...",
  "[WAIT] Bypassing local firewall restrictions...",
  "[OK] Loading OSINT subroutines...",
  "[OK] Initializing Wappalyzer engine...",
  "[OK] Ready to query CT-logs...",
  "----------------------------------------------------------------",
  "[WARNING] UNAUTHORIZED ACCESS IS STRICTLY PROHIBITED.",
  "[WARNING] ALL ACTIONS ARE LOGGED AND MONITORED.",
  "----------------------------------------------------------------",
  ">> IDENTITY CONFIRMED. WELCOME, OPERATOR.",
  ">> LAUNCHING S.T.A.R.E GRAPHICAL INTERFACE..."
];

function App() {
  const [token, setToken] = useState(localStorage.getItem('stare_token'));
  const [currentScreen, setCurrentScreen] = useState('start');
  const [isBooting, setIsBooting] = useState(false);
  const [bootText, setBootText] = useState([]);

  const handleLogin = (newToken) => {
    localStorage.setItem('stare_token', newToken);
    setToken(newToken);
    setIsBooting(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('stare_token');
    setToken(null);
  };

  useEffect(() => {
    if (!isBooting) return;
    
    let currentLine = 0;
    // Интервал увеличен до 150мс для более медленного и пафосного появления
    const interval = setInterval(() => {
      if (currentLine < BOOT_MESSAGES.length) {
        setBootText(prev => [...prev, BOOT_MESSAGES[currentLine]]);
        currentLine++;
      } else {
        clearInterval(interval);
        setTimeout(() => { 
          setIsBooting(false); 
          setBootText([]); 
        }, 1200); // Пауза перед появлением интерфейса
      }
    }, 150);
    
    return () => clearInterval(interval);
  }, [isBooting]);

  if (isBooting) {
    return (
      <div className="boot-screen">
        <div className="boot-content">
          {bootText.map((line, i) => (
            <div key={i} className={line && (line.includes('WARNING') || line.includes('WELCOME')) ? 'highlight' : ''}>
              {line}
            </div>
          ))}
          <span className="cursor">_</span>
        </div>
      </div>
    );
  }

  // Dev-only benchmark: /?bench=5000
  if (import.meta.env.DEV) {
    const bench = new URLSearchParams(window.location.search).get('bench');
    if (bench) {
      const n = Math.max(100, parseInt(bench, 10) || 5000);
      return (
        <div style={{ position: 'fixed', inset: 0, background: '#050505' }}>
          <GraphVisualizer data={buildBenchData(n)} />
        </div>
      );
    }
  }

  if (!token) return <LoginScreen onLogin={handleLogin} />;

  return (
    <>
      {currentScreen === 'start' && (
        <StartScreen onStart={() => setCurrentScreen('panel')} onLogout={handleLogout} />
      )}
      {currentScreen === 'panel' && (
        <MainScreen onBack={() => setCurrentScreen('start')} onLogout={handleLogout} />
      )}
    </>
  );
}

export default App;