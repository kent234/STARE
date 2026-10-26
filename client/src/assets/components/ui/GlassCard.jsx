import React from 'react';
import './GlassCard.css';

function GlassCard({ 
  children,
  title,
  size = 'medium',
  outline = false,
  className = ''
}) {
  
  const cardClasses = `
    glass-card 
    ${size !== 'medium' ? `glass-card--${size}` : ''} 
    ${outline ? 'glass-card--outline' : ''} 
    ${className}
  `.trim();

  return (
    <div className={cardClasses}>
      {title && (
        <h2 className="glass-card__title">
          {title}
        </h2>
      )}
      
      <div className="glass-card__content">
        {children}
      </div>
      
    </div>
  );
}

export default GlassCard;