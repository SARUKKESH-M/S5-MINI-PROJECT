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
  const isSuppressed = isFalsePositive || (feedback?.status === 'ACTIVE' && !feedback?.is_expired && !feedback?.legacy_ambiguous);
  const isExpired = feedback?.is_expired || false;
  const isLegacyAmbiguous = feedback?.legacy_ambiguous || false;

  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [reasonCode, setReasonCode] = useState(feedback?.reason_code || 'FALSE_POSITIVE');
  const [reasonComment, setReasonComment] = useState(feedback?.reason || '');
  const [expiryOption, setExpiryOption] = useState('none');
  const [customExpiry, setCustomExpiry] = useState('');

  const commentRequired = ['ACCEPTED_RISK', 'EXTERNAL_SANITIZATION', 'OTHER'].includes(reasonCode);

  const calculateExpiresAt = () => {
    if (expiryOption === 'none') return null;
    const now = new Date();
    if (expiryOption === '30d') {
      now.setDate(now.getDate() + 30);
      return now.toISOString();
    }
    if (expiryOption === '90d') {
      now.setDate(now.getDate() + 90);
      return now.toISOString();
    }
    if (expiryOption === 'custom') {
      if (!customExpiry) return null;
      const d = new Date(customExpiry);
      return isNaN(d.getTime()) ? null : d.toISOString();
    }
    return null;
  };

  const handleOpenModal = () => {
    setReasonCode(feedback?.reason_code || 'FALSE_POSITIVE');
    setReasonComment(feedback?.reason || '');
    setErrorMsg('');
    setShowModal(true);
  };

  const handleSubmitFeedback = async (e) => {
    if (e) e.preventDefault();
    if (!analysisId || !findingId || loading) return;

    if (commentRequired && (!reasonComment || reasonComment.trim().length < 5)) {
      setErrorMsg('Comment is required (at least 5 characters) for this reason.');
      return;
    }
    if (reasonComment && reasonComment.length > 1000) {
      setErrorMsg('Comment must be at most 1000 characters.');
      return;
    }

    const expiresAt = calculateExpiresAt();
    if (expiryOption === 'custom' && !expiresAt) {
      setErrorMsg('Please select a valid future expiration date.');
      return;
    }

    setLoading(true);
    setErrorMsg('');
    try {
      const res = await markFalsePositive(
        analysisId,
        findingId,
        reasonComment.trim(),
        repositoryId,
        reasonCode,
        expiresAt
      );
      setShowModal(false);
      if (onFeedbackChange) onFeedbackChange({ findingId, suppressed: true, res });
    } catch (err) {
      setErrorMsg(err.message || 'Failed to submit suppression feedback');
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = async () => {
    if (!analysisId || !findingId || loading) return;
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await revokeFalsePositive(analysisId, findingId);
      setShowModal(false);
      if (onFeedbackChange) onFeedbackChange({ findingId, suppressed: false, res });
    } catch (err) {
      setErrorMsg(err.message || 'Failed to revoke suppression');
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
          {/* Status Badges */}
          {isExpired && (
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              padding: '2px 6px',
              borderRadius: 'var(--radius-xs)',
              border: '1px solid rgba(239, 68, 68, 0.4)',
              backgroundColor: 'rgba(239, 68, 68, 0.12)',
              color: 'var(--status-critical, #ef4444)',
              fontFamily: 'var(--font-mono)',
              fontSize: '10px',
              fontWeight: 700,
            }}>
              EXPIRED SUPPRESSION
            </span>
          )}

          {isLegacyAmbiguous && (
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              padding: '2px 6px',
              borderRadius: 'var(--radius-xs)',
              border: '1px solid rgba(59, 130, 246, 0.4)',
              backgroundColor: 'rgba(59, 130, 246, 0.12)',
              color: '#3b82f6',
              fontFamily: 'var(--font-mono)',
              fontSize: '10px',
              fontWeight: 700,
            }}>
              LEGACY FEEDBACK (RE-CONFIRMATION REQUIRED)
            </span>
          )}

          {isSuppressed && (
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '4px',
              padding: '2px 6px',
              borderRadius: 'var(--radius-xs)',
              border: '1px solid var(--secondary-amber)',
              backgroundColor: 'rgba(245, 158, 11, 0.12)',
              color: 'var(--secondary-amber)',
              fontFamily: 'var(--font-mono)',
              fontSize: '10px',
              fontWeight: 600,
            }}>
              <span className="material-symbols-outlined" style={{ fontSize: '12px' }}>
                check_circle
              </span>
              {feedback?.reason_code || 'SUPPRESSED'}
            </span>
          )}

          {analysisId && findingId && (
            <button
              onClick={handleOpenModal}
              disabled={loading}
              title="Configure suppression feedback"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
                padding: '2px 8px',
                borderRadius: 'var(--radius-xs)',
                border: isSuppressed ? '1px solid var(--secondary-amber)' : '1px solid var(--border-subtle)',
                backgroundColor: isSuppressed ? 'rgba(245, 158, 11, 0.08)' : 'var(--bg-void-lowest)',
                color: isSuppressed ? 'var(--secondary-amber)' : 'var(--text-dim)',
                fontFamily: 'var(--font-mono)',
                fontSize: '10px',
                fontWeight: 600,
                cursor: loading ? 'wait' : 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '12px' }}>
                {isSuppressed ? 'edit_note' : 'flag'}
              </span>
              {isSuppressed ? 'MANAGE SUPPRESSION' : 'SUPPRESS / REVIEW'}
            </button>
          )}

          <LabelCaps style={{ fontSize: '10px' }}>
            LINES {lineStart || 1}-{lineEnd || 1}
          </LabelCaps>
        </div>
      </div>

      {/* Minimal Feedback Dialog */}
      {showModal && (
        <div style={{
          marginTop: '8px',
          padding: '12px',
          backgroundColor: 'var(--bg-void-lowest)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-xs)',
          fontFamily: 'var(--font-mono)',
          fontSize: '11px',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', alignItems: 'center' }}>
            <span style={{ fontWeight: 700, color: 'var(--text-on-surface)' }}>
              FINDING SUPPRESSION / FEEDBACK
            </span>
            <button
              onClick={() => setShowModal(false)}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-dim)',
                cursor: 'pointer',
                fontSize: '14px',
              }}
            >
              ✕
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginBottom: '8px' }}>
            <div>
              <label style={{ display: 'block', color: 'var(--text-dim)', marginBottom: '4px' }}>
                REASON TAXONOMY *
              </label>
              <select
                value={reasonCode}
                onChange={(e) => setReasonCode(e.target.value)}
                style={{
                  width: '100%',
                  padding: '4px',
                  backgroundColor: 'var(--bg-void-mid, #111)',
                  color: 'var(--text-on-surface)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-xs)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                }}
              >
                <option value="FALSE_POSITIVE">False Positive</option>
                <option value="ACCEPTED_RISK">Accepted Risk</option>
                <option value="TEST_OR_MOCK">Test / Mock Harness</option>
                <option value="EXTERNAL_SANITIZATION">Upstream Sanitized</option>
                <option value="OTHER">Other</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', color: 'var(--text-dim)', marginBottom: '4px' }}>
                EXPIRATION
              </label>
              <select
                value={expiryOption}
                onChange={(e) => setExpiryOption(e.target.value)}
                style={{
                  width: '100%',
                  padding: '4px',
                  backgroundColor: 'var(--bg-void-mid, #111)',
                  color: 'var(--text-on-surface)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-xs)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                }}
              >
                <option value="none">No Expiration</option>
                <option value="30d">30 Days</option>
                <option value="90d">90 Days</option>
                <option value="custom">Custom Date</option>
              </select>
            </div>
          </div>

          {expiryOption === 'custom' && (
            <div style={{ marginBottom: '8px' }}>
              <label style={{ display: 'block', color: 'var(--text-dim)', marginBottom: '4px' }}>
                CUSTOM EXPIRATION (UTC)
              </label>
              <input
                type="datetime-local"
                value={customExpiry}
                onChange={(e) => setCustomExpiry(e.target.value)}
                style={{
                  width: '100%',
                  padding: '4px',
                  backgroundColor: 'var(--bg-void-mid, #111)',
                  color: 'var(--text-on-surface)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-xs)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                }}
              />
            </div>
          )}

          <div style={{ marginBottom: '8px' }}>
            <label style={{ display: 'block', color: 'var(--text-dim)', marginBottom: '4px' }}>
              COMMENT {commentRequired ? '(REQUIRED >= 5 chars)' : '(OPTIONAL)'}
            </label>
            <textarea
              rows={2}
              maxLength={1000}
              value={reasonComment}
              onChange={(e) => setReasonComment(e.target.value)}
              placeholder={commentRequired ? 'Enter detailed justification (required)...' : 'Optional notes...'}
              style={{
                width: '100%',
                padding: '4px',
                backgroundColor: 'var(--bg-void-mid, #111)',
                color: 'var(--text-on-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-xs)',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                resize: 'vertical',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            {isSuppressed ? (
              <button
                type="button"
                onClick={handleRevoke}
                disabled={loading}
                style={{
                  padding: '4px 10px',
                  backgroundColor: 'rgba(239, 68, 68, 0.15)',
                  border: '1px solid rgba(239, 68, 68, 0.4)',
                  borderRadius: 'var(--radius-xs)',
                  color: 'var(--status-critical, #ef4444)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  fontWeight: 600,
                  cursor: loading ? 'wait' : 'pointer',
                }}
              >
                REVOKE SUPPRESSION
              </button>
            ) : <div />}

            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                type="button"
                onClick={() => setShowModal(false)}
                disabled={loading}
                style={{
                  padding: '4px 10px',
                  backgroundColor: 'transparent',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-xs)',
                  color: 'var(--text-dim)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  cursor: 'pointer',
                }}
              >
                CANCEL
              </button>
              <button
                type="button"
                onClick={handleSubmitFeedback}
                disabled={loading}
                style={{
                  padding: '4px 10px',
                  backgroundColor: 'var(--secondary-amber)',
                  border: 'none',
                  borderRadius: 'var(--radius-xs)',
                  color: '#000',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  fontWeight: 700,
                  cursor: loading ? 'wait' : 'pointer',
                }}
              >
                {loading ? 'SAVING...' : 'SAVE SUPPRESSION'}
              </button>
            </div>
          </div>
        </div>
      )}

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
