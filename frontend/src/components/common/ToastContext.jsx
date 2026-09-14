import React, { createContext, useContext, useState, useCallback, useRef } from 'react';

const ToastContext = createContext(null);

let toastIdCounter = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const timersRef = useRef(new Map());

  const removeToast = useCallback((id) => {
    // Clear any active timer
    if (timersRef.current.has(id)) {
      clearTimeout(timersRef.current.get(id));
      timersRef.current.delete(id);
    }
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback((message, type = 'info', duration = 4500) => {
    if (!message || typeof message !== 'string') return;

    const id = ++toastIdCounter;
    const newToast = { id, message, type };

    setToasts((prev) => {
      // Prevent duplicate spam of identical message and type within active toasts
      const exists = prev.some((t) => t.message === message && t.type === type);
      if (exists) return prev;
      // Limit to 4 simultaneous toasts
      const truncated = prev.slice(-3);
      return [...truncated, newToast];
    });

    if (duration > 0) {
      const timer = setTimeout(() => {
        removeToast(id);
      }, duration);
      timersRef.current.set(id, timer);
    }

    return id;
  }, [removeToast]);

  const toast = useMemoHelpers(addToast, removeToast);

  return (
    <ToastContext.Provider value={toast}>
      {children}
      {/* Toast Render Container */}
      <aside
        className="cs-toast-container"
        aria-live="polite"
        aria-label="Application notifications"
        role="region"
      >
        {toasts.map((t) => {
          let typeIcon = 'ℹ️';
          let borderAccent = '#6366F1';

          if (t.type === 'success') {
            typeIcon = '✓';
            borderAccent = '#10B981';
          } else if (t.type === 'error') {
            typeIcon = '✕';
            borderAccent = '#EF4444';
          } else if (t.type === 'warning') {
            typeIcon = '⚠';
            borderAccent = '#F59E0B';
          }

          return (
            <div
              key={t.id}
              className={`cs-toast cs-toast-${t.type}`}
              style={{ borderLeftColor: borderAccent }}
              role={t.type === 'error' ? 'alert' : 'status'}
            >
              <div className="cs-toast-icon" aria-hidden="true">
                {typeIcon}
              </div>
              <div className="cs-toast-message">
                {t.message}
              </div>
              <button
                type="button"
                className="cs-toast-close"
                onClick={() => removeToast(t.id)}
                aria-label="Dismiss notification"
                title="Dismiss"
              >
                ×
              </button>
            </div>
          );
        })}
      </aside>
    </ToastContext.Provider>
  );
}

function useMemoHelpers(addToast, removeToast) {
  return React.useMemo(() => ({
    show: (msg, type, duration) => addToast(msg, type, duration),
    success: (msg, duration) => addToast(msg, 'success', duration),
    error: (msg, duration) => addToast(msg, 'error', duration || 6000),
    warning: (msg, duration) => addToast(msg, 'warning', duration),
    info: (msg, duration) => addToast(msg, 'info', duration),
    dismiss: (id) => removeToast(id),
  }), [addToast, removeToast]);
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    // Fallback safe no-op if used outside ToastProvider
    return {
      show: () => {},
      success: () => {},
      error: () => {},
      warning: () => {},
      info: () => {},
      dismiss: () => {},
    };
  }
  return context;
}
