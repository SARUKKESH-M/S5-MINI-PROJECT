import React, { useState, useEffect } from 'react';
import StatusPip from './StatusPip';
import { getPlatformHealth, getPlatformInfo } from '../services/apiClient';

export default function IntelligenceBar() {
  const [systemState, setSystemState] = useState({
    status: 'green',
    version: '1.1.0',
    service: 'CodeSentinel',
    title: 'Engine Status: Operational'
  });

  useEffect(() => {
    let isMounted = true;
    const fetchSummary = async () => {
      try {
        const [healthRes, infoRes] = await Promise.allSettled([
          getPlatformHealth(),
          getPlatformInfo()
        ]);
        if (!isMounted) return;

        let statusColor = 'green';
        let statusTitle = 'Engine Status: Operational';
        let versionStr = '1.1.0';
        let serviceStr = 'CodeSentinel';

        if (healthRes.status === 'fulfilled' && healthRes.value) {
          const h = healthRes.value;
          if (h.status === 'healthy') {
            statusColor = 'green';
            statusTitle = `Platform: HEALTHY (${h.environment || 'production'})`;
          } else {
            statusColor = 'amber';
            statusTitle = `Platform: ${h.status?.toUpperCase() || 'DEGRADED'}`;
          }
          if (h.version) versionStr = h.version;
          if (h.service) serviceStr = h.service;
        } else if (healthRes.status === 'rejected') {
          statusColor = 'amber';
          statusTitle = 'Platform Health: OFFLINE / UNREACHABLE';
        }

        if (infoRes.status === 'fulfilled' && infoRes.value) {
          const info = infoRes.value;
          if (info.version) versionStr = info.version;
          if (info.service) serviceStr = info.service;
        }

        setSystemState({
          status: statusColor,
          version: versionStr,
          service: serviceStr,
          title: statusTitle
        });
      } catch {
        if (isMounted) {
          setSystemState((prev) => ({
            ...prev,
            status: 'amber',
            title: 'Platform: UNREACHABLE'
          }));
        }
      }
    };

    fetchSummary();
    return () => { isMounted = false; };
  }, []);

  return (
    <header className="intelligence-bar">
      {/* CLI Terminal Search Prompt */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, maxWidth: '640px' }}>
        <span style={{ color: 'var(--primary-cyan)', fontWeight: 'bold', fontSize: '15px' }}>&gt;</span>
        <input
          type="text"
          placeholder="SEARCH SECURITY FINDINGS, REPOSITORIES, OR CLI COMMANDS..."
          style={{
            background: 'transparent',
            border: 'none',
            outline: 'none',
            color: 'var(--text-on-surface)',
            fontFamily: 'var(--font-mono)',
            fontSize: '13px',
            width: '100%'
          }}
          readOnly
        />
      </div>

      {/* Health Indicator & System Version Metadata */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', color: 'var(--text-on-surface-variant)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <StatusPip status={systemState.status} title={systemState.title} />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
            {systemState.service.toUpperCase()} v{systemState.version}
          </span>
        </div>
        <div style={{ borderLeft: '1px solid var(--border-subtle)', height: '16px' }} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-dim)' }}>
          {systemState.status === 'green' ? 'ENGINE ONLINE' : 'DEGRADED'}
        </span>
      </div>
    </header>
  );
}
