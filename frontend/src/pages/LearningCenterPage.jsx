import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import DataPanel from '../components/DataPanel';
import MetricCard from '../components/MetricCard';
import SeverityBadge from '../components/SeverityBadge';
import LabelCaps from '../components/LabelCaps';
import StatusPip from '../components/StatusPip';
import PrimaryButton from '../components/PrimaryButton';
import SecondaryButton from '../components/SecondaryButton';
import CodeViewer from '../components/CodeViewer';
import EvidenceSnippet from '../components/EvidenceSnippet';
import { getPlatformPolicies } from '../services/apiClient';

export default function LearningCenterPage() {
  const navigate = useNavigate();

  // 1. Real platform policy profiles from GET /platform/policies
  const [platformPolicies, setPlatformPolicies] = useState([]);
  const [selectedPolicyName, setSelectedPolicyName] = useState('default');
  const [policiesLoading, setPoliciesLoading] = useState(true);

  // 2. Educational Vulnerability Catalog & Normalization Examples
  const educationalCatalog = [
    {
      id: 'EDU-01',
      pattern_name: 'Command Injection Risk',
      severity: 'critical',
      cwe: 'CWE-78: OS Command Injection',
      detection_mechanism: 'AST CallNode targeting `os.system` or `subprocess.Popen(..., shell=True)` with dynamic parameters.',
      remediation_guidance: 'Use argument lists with `subprocess.run(["cmd", arg])` and avoid `shell=True` to prevent arbitrary command concatenation.',
      normalization_criteria: 'Genuine security violation in production code. Legitimate test mocks must be excluded via path scope rules.',
      example_lines: [
        '# Vulnerable: User input passed to shell',
        'import os',
        'def execute_backup(target_path):',
        '    os.system("tar -czf backup.tar.gz " + target_path)  # INJECTION RISK',
        '',
        '# Remediated: Parameterized execution without shell',
        'import subprocess',
        'def execute_backup_safe(target_path):',
        '    subprocess.run(["tar", "-czf", "backup.tar.gz", target_path], check=True)'
      ],
      highlightRange: { start: 4, end: 4 }
    },
    {
      id: 'EDU-02',
      pattern_name: 'Arbitrary Dynamic Code Execution',
      severity: 'critical',
      cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
      detection_mechanism: 'AST CallNode targeting builtins `eval()` or `exec()` with non-constant expressions.',
      remediation_guidance: 'Replace `eval()` with `ast.literal_eval()` for literal data structures, or use explicit dictionary mapping for dynamic dispatch.',
      normalization_criteria: 'Strictly prohibited by production security gates. High risk of remote code execution.',
      example_lines: [
        '# Vulnerable: Dynamic eval of untrusted string',
        'def parse_config_value(raw_str):',
        '    return eval(raw_str)  # ARBITRARY CODE EXECUTION',
        '',
        '# Remediated: Safe literal evaluation',
        'import ast',
        'def parse_config_value_safe(raw_str):',
        '    return ast.literal_eval(raw_str)'
      ],
      highlightRange: { start: 3, end: 3 }
    },
    {
      id: 'EDU-03',
      pattern_name: 'Hardcoded Secret Assignment',
      severity: 'critical',
      cwe: 'CWE-798: Use of Hard-coded Credentials',
      detection_mechanism: 'AST AssignNode assigning high-entropy string literals to variable keys matching credential regexes.',
      remediation_guidance: 'Retrieve credentials at runtime via environment variables (`os.getenv`) or vault secret providers.',
      normalization_criteria: 'Test mock credentials in `tests/` directories can be safely excluded by configuring repository path filters.',
      example_lines: [
        '# Vulnerable: Literal API key in source',
        'API_KEY = "sk-live-9823478923489234"  # HARDCODED SECRET',
        '',
        '# Remediated: Dynamic runtime environment lookup',
        'import os',
        'API_KEY = os.getenv("API_KEY")'
      ],
      highlightRange: { start: 2, end: 2 }
    },
    {
      id: 'EDU-04',
      pattern_name: 'Unsafe Object Deserialization',
      severity: 'high',
      cwe: 'CWE-502: Deserialization of Untrusted Data',
      detection_mechanism: 'AST CallNode invoking `pickle.loads()` on input derived from network sockets or request cookies.',
      remediation_guidance: 'Use safe serialization formats like JSON, MessagePack, or signed cryptographic envelopes (HMAC).',
      normalization_criteria: 'Review finding; permitted only in trusted intra-cluster RPC if cryptographically verified.',
      example_lines: [
        '# Vulnerable: Untrusted pickle deserialization',
        'import pickle',
        'def handle_session(raw_cookie):',
        '    return pickle.loads(raw_cookie)  # UNSAFE DESERIALIZATION',
        '',
        '# Remediated: Standard JSON parsing',
        'import json',
        'def handle_session_safe(raw_cookie):',
        '    return json.loads(raw_cookie)'
      ],
      highlightRange: { start: 4, end: 4 }
    }
  ];

  const [selectedPatternId, setSelectedPatternId] = useState('EDU-01');
  const activePattern = educationalCatalog.find(p => p.id === selectedPatternId) || educationalCatalog[0];

  // Fetch real policy profiles from backend
  useEffect(() => {
    let isMounted = true;
    getPlatformPolicies()
      .then((policies) => {
        if (!isMounted) return;
        if (Array.isArray(policies) && policies.length > 0) {
          setPlatformPolicies(policies);
          setSelectedPolicyName(policies[0].name);
        }
      })
      .catch(() => {
        // Handled gracefully
      })
      .finally(() => {
        if (isMounted) setPoliciesLoading(false);
      });

    return () => { isMounted = false; };
  }, []);

  const activePolicy = platformPolicies.find(p => p.name === selectedPolicyName) || null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
      
      {/* 1. Page Context & Header */}
      <DataPanel status="cyan">
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <LabelCaps style={{ fontSize: '11px', color: 'var(--primary-cyan)' }}>
                EDUCATIONAL WORKSPACE &amp; SECURITY POLICY GUIDANCE
              </LabelCaps>
              <StatusPip status="green" title="Educational Knowledge Base Active" />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--status-green)' }}>
                STATIC AST + STEP 6O RULES
              </span>
            </div>
            <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 700, color: 'var(--text-on-surface)' }}>
              Security Learning Center
            </h1>
            <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--text-on-surface-variant)' }}>
              Reference guide for CodeSentinel AST signal patterns, false-positive normalization criteria, and server-side policy enforcement profiles.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <SecondaryButton icon="alt_route" onClick={() => navigate('/pr-review')}>
              PR REVIEW
            </SecondaryButton>
            <SecondaryButton icon="psychology" onClick={() => navigate('/ai-analysis')}>
              AI ANALYSIS
            </SecondaryButton>
            <SecondaryButton icon="dashboard" onClick={() => navigate('/command-center')}>
              COMMAND CENTER
            </SecondaryButton>
          </div>
        </div>
      </DataPanel>

      {/* 2. Educational Principles Bento Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        <MetricCard
          label="AST PARSING PRINCIPLE"
          value="NON-EXEC"
          delta="Static Text Inspection"
          accentColor="cyan"
        />
        <MetricCard
          label="FALSE POSITIVES"
          value="SCOPE-BASED"
          delta="Path Exclusions &amp; Context"
          accentColor="amber"
        />
        <MetricCard
          label="GATE AUTHORITY"
          value="SERVER-SIDE"
          delta="Fail-Closed Verification"
          accentColor="red"
        />
        <MetricCard
          label="SECURITY STANDARDS"
          value="CWE / OWASP"
          delta="Evidence Grounding"
          accentColor="green"
        />
      </div>

      {/* 3. Real Server-Side Security Policy Profiles (from /platform/policies) */}
      <DataPanel title="PRODUCTION SECURITY POLICY ENFORCEMENT PROFILES" status="green">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <LabelCaps style={{ fontSize: '10px' }}>SELECT PROFILE TO INSPECT:</LabelCaps>
              {platformPolicies.map((p) => {
                const isSelected = p.name === selectedPolicyName;
                return (
                  <button
                    key={p.name}
                    type="button"
                    onClick={() => setSelectedPolicyName(p.name)}
                    style={{
                      backgroundColor: isSelected ? 'var(--primary-cyan)' : 'var(--bg-void-lowest)',
                      color: isSelected ? 'var(--text-inverse)' : 'var(--text-on-surface-variant)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-xs)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '11px',
                      fontWeight: 700,
                      padding: '5px 12px',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease-in-out'
                    }}
                  >
                    {p.name.toUpperCase()}
                  </button>
                );
              })}
            </div>

            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-dim)' }}>
              Server-enforced via backend policy engine
            </span>
          </div>

          {activePolicy && (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '12px',
              padding: '14px',
              backgroundColor: 'var(--bg-void-lowest)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-xs)',
              fontFamily: 'var(--font-mono)',
              fontSize: '12px'
            }}>
              <div>
                <span style={{ color: 'var(--text-dim)', display: 'block', fontSize: '10px' }}>SEVERITY THRESHOLD</span>
                <span style={{ color: 'var(--primary-cyan)', fontWeight: 700, fontSize: '14px' }}>{activePolicy.severity_threshold}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-dim)', display: 'block', fontSize: '10px' }}>MAX AUDITED FILES</span>
                <span style={{ color: 'var(--text-on-surface)', fontWeight: 600 }}>{activePolicy.max_files}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-dim)', display: 'block', fontSize: '10px' }}>GATE ACTIONS</span>
                <span style={{ color: 'var(--text-on-surface)' }}>{activePolicy.review_action} / {activePolicy.block_action}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-dim)', display: 'block', fontSize: '10px' }}>BLOCK ON CRITICAL</span>
                <span style={{ color: activePolicy.block_on_critical ? 'var(--critical-red)' : 'var(--text-dim)', fontWeight: 700 }}>
                  {activePolicy.block_on_critical ? 'ENABLED' : 'DISABLED'}
                </span>
              </div>
            </div>
          )}
        </div>
      </DataPanel>

      {/* 4. Educational Vulnerability Catalog & Code Remediation Patterns */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        
        {/* Left: Pattern Selection (5 cols) */}
        <div style={{ gridColumn: 'span 5' }}>
          <DataPanel title="VULNERABILITY PATTERNS CATALOG" status="cyan">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {educationalCatalog.map((pattern) => {
                const isSelected = pattern.id === selectedPatternId;
                return (
                  <div
                    key={pattern.id}
                    onClick={() => setSelectedPatternId(pattern.id)}
                    style={{
                      padding: '12px',
                      backgroundColor: isSelected ? 'var(--panel-bg-high)' : 'var(--bg-void-lowest)',
                      border: isSelected ? '1px solid var(--primary-cyan)' : '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-xs)',
                      cursor: 'pointer',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px',
                      transition: 'all 0.15s ease-in-out'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <LabelCaps style={{ fontSize: '10px' }}>{pattern.id}</LabelCaps>
                      <SeverityBadge severity={pattern.severity} />
                    </div>
                    <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-on-surface)' }}>
                      {pattern.pattern_name}
                    </div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--secondary-amber)' }}>
                      {pattern.cwe}
                    </div>
                  </div>
                );
              })}
            </div>
          </DataPanel>
        </div>

        {/* Right: Detailed Remediation Guide & Example (7 cols) */}
        <div style={{ gridColumn: 'span 7' }}>
          <DataPanel
            title={`PATTERN GUIDE: ${activePattern.pattern_name.toUpperCase()}`}
            status="cyan"
            action={<SeverityBadge severity={activePattern.severity} />}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              
              {/* Detection Mechanism */}
              <div style={{ padding: '10px 12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)' }}>
                <LabelCaps style={{ fontSize: '10px', color: 'var(--primary-cyan)' }}>DETECTION MECHANISM</LabelCaps>
                <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-on-surface)', lineHeight: 1.5 }}>
                  {activePattern.detection_mechanism}
                </p>
              </div>

              {/* Remediation Guidance */}
              <div style={{ padding: '10px 12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)' }}>
                <LabelCaps style={{ fontSize: '10px', color: 'var(--status-green)' }}>REMEDIATION GUIDANCE</LabelCaps>
                <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-on-surface)', lineHeight: 1.5 }}>
                  {activePattern.remediation_guidance}
                </p>
              </div>

              {/* False Positive Normalization Criteria */}
              <div style={{ padding: '10px 12px', backgroundColor: 'var(--bg-void-lowest)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)' }}>
                <LabelCaps style={{ fontSize: '10px', color: 'var(--secondary-amber)' }}>NORMALIZATION &amp; TUNING CRITERIA</LabelCaps>
                <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-on-surface)', lineHeight: 1.5 }}>
                  {activePattern.normalization_criteria}
                </p>
              </div>

              {/* Code Example Viewer */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <LabelCaps style={{ fontSize: '10px' }}>REMEDIATION CODE COMPARISON</LabelCaps>
                <CodeViewer
                  lines={activePattern.example_lines}
                  startLine={1}
                  highlightRange={activePattern.highlightRange}
                />
              </div>

            </div>
          </DataPanel>
        </div>

      </div>

    </div>
  );
}
