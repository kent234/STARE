import React from 'react';
import './GlassInput.css';

function GlassInput({
  label,
  placeholder = '',
  value,
  onChange,
  type = 'text',
  size = 'medium',
  error = false,
  errorText = '',
  className = ''
}) {
  
  const inputClasses = `
    glass-input 
    ${size !== 'medium' ? `glass-input--${size}` : ''} 
    ${error ? 'glass-input--error' : ''} 
    ${className}
  `.trim();

  return (
    <div className="glass-input-container">
      
      {label && (
        <label className="glass-input__label">
          {label}
        </label>
      )}
      
      <input
        type={type}
        className={inputClasses}
        placeholder={placeholder}
        value={value}
        onChange={onChange}
      />
      
      {error && errorText && (
        <span className="glass-input__error">
          {errorText}
        </span>
      )}
      
    </div>
  );
}

export default GlassInput;