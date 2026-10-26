import React from 'react';
import './GlassButton.css';

function GlassButton({ 
  children,
  onClick,
  size = 'medium',
  disabled = false,
  className = ''
}) {
  
  const buttonClasses = `
    glass-button 
    ${size !== 'medium' ? `glass-button--${size}` : ''} 
    ${disabled ? 'glass-button--disabled' : ''} 
    ${className}
  `.trim();

  return (
    <button
      className={buttonClasses}
      onClick={onClick}
      disabled={disabled}
      type="button"
    >
      {children}
    </button>
  );
}

export default GlassButton;