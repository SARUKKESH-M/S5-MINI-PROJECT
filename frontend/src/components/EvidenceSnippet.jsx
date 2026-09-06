import React, { useState, useEffect } from 'react';
import LabelCaps from './LabelCaps';
import { markFalsePositive, revokeFalsePositive } from '../services/apiClient';

export default function EvidenceSnippet({
  documentId,
  lineStart,
  lineEnd,
  signalType,
  signalName,
  snippetLines = [],
  analysisId,
  findingId,
  repositoryId,
  isFalsePositive = false,
  feedback = null,
  onFeedbackChange,
}) {
  const [suppressed, setSuppressed] = useState(isFalsePositive || feedback?.status === 'ACTIVE');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  useEffect(() => {
    setSuppressed(isFalsePositive || feedback?.status === 'ACTIVE');
  }, [isFalsePositive, feedback]);

  const handleToggleFalsePositive = async () => {
    if (!analysisId || !findingId || loading) return;
    setLoading(true);
    setErrorMsg('');
    try {
      if (suppressed) {
        const res = await revokeFalsePositive(analysisId, findingId);
        setSuppressed(false);
        if (onFeedbackChange) onFeedbackChange({ findingId, suppressed: false, res });
      } else {
        const res = await markFalsePositive(analysisId, findingId, 'Marked by reviewer via UI inspector', repositoryId);
        setSuppressed(true);
        if (onFeedbackChange) onFeedbackChange({ findingId, suppressed: true, res });
      }
    } catch (err) {
      setErrorMsg(err.message || 'Failed to update false-positive feedback');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="evidence-snippet">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="material-symbols-outlined" style={{ fontSize: '16px', color: 'var(--primary-cyan)' }}>
            description
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 600 }}>
            {documentId || 'FILE_PATH_PLACEHOLDER'}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {analysisId && findingId && (
            <button
              onClick={handleToggleFalsePositive}
              disabled={loading}
              title={suppressed ? 'Restore finding as active' : 'Mark as false positive'}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
                padding: '2px 8px',
                borderRadius: 'var(--radius-xs)',
                border: suppressed ? '1px solid var(--secondary-amber)' : '1px solid var(--border-subtle)',
                backgroundColor: suppressed ? 'rgba(245, 158, 11, 0.12)' : 'var(--bg-void-lowest)',
                color: suppressed ? 'var(--secondary-amber)' : 'var(--text-dim)',
                fontFamily: 'var(--font-mono)',
                fontSize: '10px',
                fontWeight: 600,
                cursor: loading ? 'wait' : 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '12px' }}>
                {suppressed ? 'check_circle' : 'flag'}
              </span>
              {loading
                ? 'UPDATING...'
                : suppressed
                ? 'FALSE POSITIVE (UNDO)'
                : 'MARK FALSE POSITIVE'}
            </button>
          )}
          <LabelCaps style={{ fontSize: '10px' }}>
            LINES {lineStart || 1}-{lineEnd || 1}
          </LabelCaps>
        </div>
      </div>

      {errorMsg && (
        <div style={{
          marginTop: '4px',
          padding: '4px 8px',
          borderRadius: 'var(--radius-xs)',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          color: 'var(--status-critical)',
          fontSize: '11px',
          fontFamily: 'var(--font-mono)'
        }}>
          {errorMsg}
        </div>
      )}

      {(signalType || signalName) && (
        <div style={{ display: 'flex', gap: '12px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-on-surface-variant)' }}>
          {signalType && <span>SIGNAL: <strong>{signalType}</strong></span>}
          {signalName && <span>NAME: <strong>{signalName}</strong></span>}
        </div>
      )}

      {snippetLines.length > 0 && (
        <div style={{ marginTop: '4px' }}>
          <pre style={{
            margin: 0,
            padding: '8px 12px',
            backgroundColor: 'var(--bg-void-lowest)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-xs)',
            fontFamily: 'var(--font-mono)',
            fontSize: '12px',
            color: 'var(--text-on-surface)',
            overflowX: 'auto'
          }}>
            {snippetLines.join('\n')}
          </pre>
        </div>
      )}
    </div>
  );
}
