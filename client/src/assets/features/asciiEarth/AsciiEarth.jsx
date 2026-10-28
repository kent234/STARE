import { useEffect, useState } from 'react';
import Globe from 'ascii-globe'; 
import './AsciiEarth.css';

function AsciiEarth() {
  const [globeText, setGlobeText] = useState('');
  const [rotation, setRotation] = useState(0);

  useEffect(() => {
    const globe = new Globe({
      size: 1.2,              // размер 1 = 120x60 символов
      land: '#',              // символ для суши
      water: '.',             // символ для воды
      background: ' ',        // символ фона
      speed: 0.5,             // скорость вращения (градусов за кадр)
    });

    let animationId;
    let currentRotation = 0;

    const animate = () => {
      const text = globe.render(currentRotation);
      setGlobeText(text);
      
      currentRotation = (currentRotation + 0.5) % 360;
      
      animationId = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      if (animationId) {
        cancelAnimationFrame(animationId);
      }
    };
  }, []);

  return (
    <div className="ascii-earth-container">
      <pre className="ascii-earth">{globeText}</pre>
    </div>
  );
}

export default AsciiEarth;