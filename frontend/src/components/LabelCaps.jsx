import React from 'react';

export default function LabelCaps({ children, className = '', style = {} }) {
  return (
    <span className={`label-caps ${className}`} style={style}>
      {children}
    </span>
  );
}
