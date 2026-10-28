import React from 'react';
import AsciiEarth from '../../features/asciiEarth/AsciiEarth'; // ВЕРНУЛИ ЗЕМЛЮ
import GlassButton from '../../components/ui/GlassButton';
import './StartScreen.css';

const logoLines = [
  "███████╗████████╗ █████╗ ██████╗ ███████╗",
  "██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝",
  "███████╗   ██║   ███████║██████╔╝█████╗  ",
  "╚════██║   ██║   ██╔══██║██╔══██╗██╔══╝  ",
  "███████║   ██║   ██║  ██║██║  ██║███████╗",
  "╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝"
];

function StartScreen({ onStart }) {
  return (
    <div className="start-screen">
      
      {/* CRT эффекты */}
      <div className="scanlines"></div>
      <div className="crt-flicker"></div>
      <div className="vignette"></div>

      {/* ЛЕВАЯ ПОЛОВИНА: Земля */}
      <div className="earth-bg">
        <AsciiEarth />
      </div>

      {/* ЦЕНТРАЛЬНЫЙ ЛОГОТИП */}
      <header className="global-header">
        <div className="logo-wrapper">
          {logoLines.map((line, index) => (
            <div 
              key={index} 
              className="logo-line vhs-glitch" 
              data-text={line}
            >
              {line}
            </div>
          ))}
        </div>
        <div className="subtitle-wrapper">
          <h2 className="subtitle">&gt;&gt; SURFACE TRACKING AND RECON ENGINE &lt;&lt;</h2>
          <span className="blinking-cursor">_</span>
        </div>
      </header>

      {/* ПРАВАЯ ПОЛОВИНА: Варезный блок */}
      <main className="ui-layer">
        <div className="warez-box">
          
          <div className="box-header">[ SYSTEM.INFO ]</div>
          
          <h3 className="info-title">{'> INITIALIZE_SEQUENCE'}</h3>
          <p className="info-text">
            S.T.A.R.E. — это автономный инструмент OSINT-разведки и управления поверхностью атаки (ASM).
          </p>
          <p className="info-text">
            Сканируйте целевые домены, находите скрытые поддомены, открытые порты и уязвимости. Смотрите на инфраструктуру глазами хакера.
          </p>
          
          <div className="button-wrapper">
            <GlassButton size="large" onClick={onStart}>
              [ EXECUTE ]
            </GlassButton>
          </div>

          <div className="box-footer">
            <span>CRACKED BY S.T.A.R.E TEAM 2026</span>
          </div>

        </div>
      </main>

    </div>
  );
}

export default StartScreen;