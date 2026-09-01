import React from 'react';

export default function StatusPip({ status = 'cyan', title }) {
  return (
    <span
      className={`status-pip status-pip-${status}`}
      title={title || `Status: ${status}`}
    />
  );
}
