import React from 'react';

export default function SecondaryButton({ children, onClick, disabled = false, icon, className = '' }) {
  return (
    <button
      className={`btn-secondary ${className}`}
      onClick={onClick}
      disabled={disabled}
    >
      {icon && (
        <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>
          {icon}
        </span>
      )}
      {children}
    </button>
  );
}
