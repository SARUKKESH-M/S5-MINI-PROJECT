import React from 'react';

export default function CodeViewer({ lines = [], startLine = 1, highlightRange }) {
  return (
    <div className="code-viewer">
      {lines.map((line, idx) => {
        const lineNum = startLine + idx;
        const isHighlighted =
          highlightRange &&
          lineNum >= highlightRange.start &&
          lineNum <= highlightRange.end;

        return (
          <div
            key={lineNum}
            className="code-viewer-line"
            style={{
              backgroundColor: isHighlighted ? 'rgba(0, 240, 255, 0.08)' : undefined,
              borderLeft: isHighlighted ? '2px solid var(--primary-cyan)' : '2px solid transparent'
            }}
          >
            <span className="code-viewer-num">{lineNum}</span>
            <span className="code-viewer-text">{line}</span>
          </div>
        );
      })}
    </div>
  );
}
