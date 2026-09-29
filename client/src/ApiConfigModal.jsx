import React, { useState, useEffect } from 'react';

export default function ApiConfigModal({
  isOpen,
  onClose,
  config,
  onSave,
  onTest,
  onGetRawKey,
  testStatus,
  isSaving,
  saveNotice
}) {
  const [vtEnabled, setVtEnabled] = useState(true);
  const [vtKey, setVtKey] = useState('');
  const [vtShow, setVtShow] = useState(false);
  const [vtModified, setVtModified] = useState(false);

  const [gsbEnabled, setGsbEnabled] = useState(true);
  const [gsbKey, setGsbKey] = useState('');
  const [gsbShow, setGsbShow] = useState(false);
  const [gsbModified, setGsbModified] = useState(false);

  useEffect(() => {
    if (config) {
      setVtEnabled(config.virusTotalEnabled ?? true);
      setVtKey(config.virusTotalKeyMasked || '');
      setVtModified(false);
      setVtShow(false);

      setGsbEnabled(config.googleSafeBrowsingEnabled ?? true);
      setGsbKey(config.googleSafeBrowsingKeyMasked || '');
      setGsbModified(false);
      setGsbShow(false);
    }
  }, [config, isOpen]);

  if (!isOpen) return null;

  const handleToggleShowVt = async () => {
    if (!vtShow && !vtModified && config?.virusTotalHasKey && onGetRawKey) {
      const raw = await onGetRawKey('VirusTotal');
      if (raw) setVtKey(raw);
    }
    setVtShow(!vtShow);
  };

  const handleToggleShowGsb = async () => {
    if (!gsbShow && !gsbModified && config?.googleSafeBrowsingHasKey && onGetRawKey) {
      const raw = await onGetRawKey('GoogleSafeBrowsing');
      if (raw) setGsbKey(raw);
    }
    setGsbShow(!gsbShow);
  };

  const handleSave = (e) => {
    e?.preventDefault();
    onSave({
      virusTotalEnabled: vtEnabled,
      virusTotalKey: vtModified ? vtKey.trim() : null,
      googleSafeBrowsingEnabled: gsbEnabled,
      googleSafeBrowsingKey: gsbModified ? gsbKey.trim() : null,
    });
  };

  const getStatusBadge = (enabled, hasKey, isModified, currentKey) => {
    if (!enabled) {
      return <span className="status-badge badge-disabled">DISABLED</span>;
    }
    const effectivelyHasKey = isModified ? Boolean(currentKey && currentKey.trim()) : hasKey;
    if (effectivelyHasKey) {
      return <span className="status-badge badge-online">ONLINE</span>;
    }
    return <span className="status-badge badge-missing">KEY MISSING</span>;
  };

  const vtTest = testStatus?.VirusTotal;
  const gsbTest = testStatus?.GoogleSafeBrowsing;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div>
            <h2 className="modal-title">Threat Intelligence &amp; Antivirus APIs</h2>
            <p className="modal-subtitle">Configure external reputation feeds &amp; credentials safely</p>
          </div>
          <button className="modal-close-btn" onClick={onClose} aria-label="Close modal">
            &times;
          </button>
        </div>

        <form onSubmit={handleSave} className="modal-body">
          {saveNotice && (
            <div className={`modal-notice ${saveNotice.success ? 'notice-success' : 'notice-error'}`}>
              {saveNotice.message}
            </div>
          )}

          {/* VirusTotal v3 Section */}
          <div className="api-section">
            <div className="api-section-header">
              <div className="api-title-row">
                <span className="api-name">VirusTotal v3</span>
                {getStatusBadge(vtEnabled, config?.virusTotalHasKey, vtModified, vtKey)}
              </div>
              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={vtEnabled}
                  onChange={(e) => setVtEnabled(e.target.checked)}
                />
                <span>Enable VirusTotal Checks</span>
              </label>
            </div>

            <div className="api-input-row">
              <div className="input-with-toggle">
                <input
                  type={vtShow ? 'text' : 'password'}
                  className="modal-input"
                  placeholder="Paste VirusTotal 64-char API Key..."
                  value={vtKey}
                  onChange={(e) => {
                    setVtKey(e.target.value);
                    setVtModified(true);
                  }}
                  disabled={!vtEnabled}
                />
                <button
                  type="button"
                  className="eye-toggle-btn"
                  onClick={handleToggleShowVt}
                  disabled={!vtEnabled}
                  title={vtShow ? 'Hide Key' : 'Show Key'}
                >
                  {vtShow ? 'Hide' : 'Show'}
                </button>
              </div>

              <button
                type="button"
                className="test-btn"
                disabled={!vtEnabled || vtTest?.loading}
                onClick={() => onTest('VirusTotal', vtModified ? vtKey : null)}
              >
                {vtTest?.loading ? 'Testing...' : 'Test Key'}
              </button>
            </div>

            {vtTest && (
              <div className={`test-feedback ${vtTest.success ? 'feedback-success' : 'feedback-error'}`}>
                {vtTest.message}
              </div>
            )}
          </div>

          {/* Google Safe Browsing Section */}
          <div className="api-section">
            <div className="api-section-header">
              <div className="api-title-row">
                <span className="api-name">Google Safe Browsing v4</span>
                {getStatusBadge(gsbEnabled, config?.googleSafeBrowsingHasKey, gsbModified, gsbKey)}
              </div>
              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={gsbEnabled}
                  onChange={(e) => setGsbEnabled(e.target.checked)}
                />
                <span>Enable Safe Browsing Checks</span>
              </label>
            </div>

            <div className="api-input-row">
              <div className="input-with-toggle">
                <input
                  type={gsbShow ? 'text' : 'password'}
                  className="modal-input"
                  placeholder="Paste Google Safe Browsing API Key..."
                  value={gsbKey}
                  onChange={(e) => {
                    setGsbKey(e.target.value);
                    setGsbModified(true);
                  }}
                  disabled={!gsbEnabled}
                />
                <button
                  type="button"
                  className="eye-toggle-btn"
                  onClick={handleToggleShowGsb}
                  disabled={!gsbEnabled}
                  title={gsbShow ? 'Hide Key' : 'Show Key'}
                >
                  {gsbShow ? 'Hide' : 'Show'}
                </button>
              </div>

              <button
                type="button"
                className="test-btn"
                disabled={!gsbEnabled || gsbTest?.loading}
                onClick={() => onTest('GoogleSafeBrowsing', gsbModified ? gsbKey : null)}
              >
                {gsbTest?.loading ? 'Testing...' : 'Test Key'}
              </button>
            </div>

            {gsbTest && (
              <div className={`test-feedback ${gsbTest.success ? 'feedback-success' : 'feedback-error'}`}>
                {gsbTest.message}
              </div>
            )}
          </div>

          <div className="modal-footer">
            <button type="button" className="btn-cancel" onClick={onClose} disabled={isSaving}>
              Cancel
            </button>
            <button type="submit" className="btn-save" disabled={isSaving}>
              {isSaving ? 'Saving...' : 'Save Settings'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
