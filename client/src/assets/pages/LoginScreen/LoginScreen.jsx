import React, { useState } from 'react';
import './LoginScreen.css';

function LoginScreen({ onLogin }) {
  const [isRegister, setIsRegister] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    const endpoint = isRegister ? 'register' : 'login';
    
    try {
      const res = await fetch(`http://localhost:8080/api/auth/${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      
      if (!res.ok) {
        // Читаем реальный текст ошибки от Go-сервера
        const errorText = await res.text(); 
        throw new Error(errorText || 'Server error');
      }
      
      const data = await res.json();
      if (isRegister) {
        setIsRegister(false);
        setError('Registration successful. Please login.');
      } else {
        onLogin(data.token);
      }
    } catch (err) {
      setError(err.message); // Теперь мы увидим реальную причину
    } finally {
      setLoading(false);
    }
  };
  return (
    <div className="login-container">
      <div className="monitor-frame">
        <div className="monitor-vent"></div>
        <div className="crt-screen">
          <div className="crt-content">
            <div className="terminal-header">S.T.A.R.E SYSTEM v1.0 - SECURE LOGIN</div>
            <form onSubmit={handleSubmit} className="login-form">
              <div className="input-line">
                <span className="prompt">LOGIN:</span>
                <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus required />
              </div>
              <div className="input-line">
                <span className="prompt">PASSWD:</span>
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
              </div>
              {error && <div className={`error-msg ${error.includes('successful') ? 'success' : ''}`}>{error}</div>}
              <div className="login-actions">
                <button type="submit" disabled={loading}>{loading ? 'PROCESSING...' : (isRegister ? '[ CREATE_ACCOUNT ]' : '[ AUTHENTICATE ]')}</button>
                <span className="toggle-mode" onClick={() => { setIsRegister(!isRegister); setError(''); }}>
                  {isRegister ? '> Back to Login' : '> Register new user'}
                </span>
              </div>
            </form>
          </div>
          <div className="scanlines"></div>
          <div className="vignette"></div>
          <div className="screen-glow"></div>
        </div>
        <div className="monitor-stand"></div>
        <div className="monitor-base"></div>
      </div>
    </div>
  );
}
export default LoginScreen;