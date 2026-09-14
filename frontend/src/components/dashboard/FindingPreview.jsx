import React from 'react';
import { useNavigate } from 'react-router-dom';
import { CodeFileIcon } from './Icons';

export default function FindingPreview({ preview = null, onOpenModal = null }) {
  const navigate = useNavigate();

  const title = preview?.title || 'Command Injection Risk';
  const severity = preview?.severity || 'Critical';
  const sevKey = preview?.sevKey || 'critical';
  const fileLocation = preview?.fileLocation || 'backend/utils/execute.py:42';
  const description = preview?.description || 'User-controlled input can lead to arbitrary command execution on the server.';

  return (
    <div className="cs-finding-preview-card">
      <div className="cs-finding-preview-header">
        <h4 className="cs-card-section-title">Finding Preview</h4>
        <span className={`cs-severity-pill cs-sev-${sevKey}`}>{severity}</span>
      </div>

      <div className="cs-preview-meta">
        <div className="cs-preview-finding-name">{title}</div>
        <div className="cs-preview-file-loc">
          <CodeFileIcon size={14} color="#64748B" />
          <span>{fileLocation}</span>
        </div>
      </div>

      {/* Code Snippet Box (Illustrative syntax presentation per Rule 13) */}
      <div className="cs-preview-code-block">
        <div className="cs-code-line">
          <span className="cs-line-num">40</span>
          <span className="cs-code-content"><span className="cs-code-keyword">def</span> <span className="cs-code-func">run_command</span>(cmd):</span>
        </div>
        <div className="cs-code-line">
          <span className="cs-line-num">41</span>
          <span className="cs-code-content cs-code-comment">    # vulnerable code</span>
        </div>
        <div className="cs-code-line cs-code-line-highlight">
          <span className="cs-line-num">42</span>
          <span className="cs-code-content">    os.system(cmd)</span>
        </div>
        <div className="cs-code-line">
          <span className="cs-line-num">43</span>
          <span className="cs-code-content">    <span className="cs-code-keyword">return</span> <span className="cs-code-bool">True</span></span>
        </div>
      </div>

      {/* Explanation Box */}
      <div className="cs-preview-danger-box">
        <div className="cs-danger-label">Why is this dangerous?</div>
        <p className="cs-danger-desc">{description}</p>
      </div>


      {/* Action Button */}
      <button
        type="button"
        className="cs-preview-details-btn"
        onClick={() => {
          if (onOpenModal) {
            onOpenModal();
          } else {
            navigate('/analyze');
          }
        }}
      >
        <span>View Full Details</span>
        <span className="cs-arrow-icon">→</span>
      </button>
    </div>
  );
}
