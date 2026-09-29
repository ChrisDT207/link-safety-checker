import React, { useState, useEffect, useRef } from 'react';
import ApiConfigModal from './ApiConfigModal.jsx';

const validateUrl = (input) => {
  if (!input || !input.trim()) {
    return { valid: false, message: '' };
  }
  const trimmed = input.trim();

  // Strict check: must begin with http:// or https://
  if (!/^https?:\/\//i.test(trimmed)) {
    return {
      valid: false,
      message: 'Invalid URL format: URL must begin with http:// or https:// (e.g., https://example.com)',
    };
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return {
        valid: false,
        message: 'Invalid protocol: Only http:// and https:// URLs are supported.',
      };
    }

    const host = parsed.hostname;
    if (!host || host.includes(' ') || host.includes('\t')) {
      return { valid: false, message: 'Invalid URL: Hostname contains invalid spaces or characters.' };
    }

    const isLocalhost = host.toLowerCase() === 'localhost';
    const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
    const isIpv6 = host.startsWith('[') && host.endsWith(']');
    const isDomain = /^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(host);

    const lowerHost = host.toLowerCase();
    if (
      lowerHost.endsWith('.cs') ||
      lowerHost.endsWith('.cpp') ||
      lowerHost.endsWith('.java') ||
      lowerHost.endsWith('.py') ||
      lowerHost.endsWith('.ts') ||
      lowerHost.endsWith('.js')
    ) {
      return { valid: false, message: 'Invalid URL: Source code filename detected instead of a web domain.' };
    }

    if (!isLocalhost && !isIpv4 && !isIpv6 && !isDomain) {
      return { valid: false, message: 'Invalid URL: Missing a valid domain structure (e.g., example.com).' };
    }

    return { valid: true, message: '' };
  } catch {
    return { valid: false, message: 'Invalid URL format. Please enter a valid web address.' };
  }
};

export default function App() {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [statusText, setStatusText] = useState('');

  // API Config Modal State
  const [isConfigModalOpen, setIsConfigModalOpen] = useState(false);
  const [apiConfig, setApiConfig] = useState(null);
  const [testStatus, setTestStatus] = useState({});
  const [isSavingConfig, setIsSavingConfig] = useState(false);
  const [saveNotice, setSaveNotice] = useState(null);

  const rawKeyResolvers = useRef({});

  useEffect(() => {
    // Listen for Photino IPC messages
    const messageHandler = (rawMessage) => {
      try {
        const message = typeof rawMessage === 'string' ? JSON.parse(rawMessage) : rawMessage;

        if (message.type === 'ANALYSIS_STARTED') {
          setStatusText(`Inspecting: ${message.url}...`);
        } else if (message.type === 'ANALYSIS_RESULT') {
          setIsLoading(false);
          setStatusText('');
          setResult(message.data);
          if (message.data.errorMessage && !message.data.safetyScore) {
            setError(message.data.errorMessage);
          }
        } else if (message.type === 'API_CONFIG_DATA') {
          setApiConfig(message.data);
        } else if (message.type === 'API_CONFIG_SAVED') {
          setIsSavingConfig(false);
          setApiConfig(message.data);
          setSaveNotice({ success: true, message: 'Settings saved and updated in active memory!' });
          setTimeout(() => setSaveNotice(null), 4000);
        } else if (message.type === 'TEST_API_KEY_RESULT') {
          const res = message.data;
          setTestStatus((prev) => ({
            ...prev,
            [res.provider]: {
              loading: false,
              success: res.success,
              message: res.statusMessage,
            },
          }));
        } else if (message.type === 'RAW_API_KEY_DATA') {
          const resolver = rawKeyResolvers.current[message.provider];
          if (resolver) {
            resolver(message.key);
            delete rawKeyResolvers.current[message.provider];
          }
        } else if (message.type === 'ERROR') {
          setIsLoading(false);
          setIsSavingConfig(false);
          setStatusText('');
          setError(message.message || 'An error occurred.');
        }
      } catch (err) {
        console.error('Failed to parse IPC message:', err);
      }
    };

    if (window.external && typeof window.external.receiveMessage === 'function') {
      window.external.receiveMessage(messageHandler);
      // Fetch initial API config on startup
      window.external.sendMessage(JSON.stringify({ type: 'GET_API_CONFIG' }));
    } else {
      console.warn('Photino IPC bridge not detected (running in standalone browser).');
    }
  }, []);

  const urlValidation = validateUrl(url);

  const handleCheck = (e) => {
    e?.preventDefault();
    const targetUrl = url.trim();
    if (!targetUrl) {
      setError('Please enter a URL to check.');
      return;
    }

    const validation = validateUrl(targetUrl);
    if (!validation.valid) {
      setError(validation.message || 'Invalid URL format: URL must include http:// or https:// and a valid domain.');
      return;
    }

    setError('');
    setResult(null);
    setIsLoading(true);
    setStatusText('Sending request to security analyzer...');

    if (window.external && typeof window.external.sendMessage === 'function') {
      window.external.sendMessage(
        JSON.stringify({
          type: 'ANALYZE_URL',
          url: targetUrl,
        })
      );
    } else {
      // Fallback simulation for dev outside Photino
      setTimeout(() => {
        setIsLoading(false);
        setError('Desktop IPC bridge unavailable. Launch via LinkSafetyChecker.exe.');
      }, 1000);
    }
  };

  const openConfigModal = () => {
    setSaveNotice(null);
    setTestStatus({});
    setIsConfigModalOpen(true);
    if (window.external && typeof window.external.sendMessage === 'function') {
      window.external.sendMessage(JSON.stringify({ type: 'GET_API_CONFIG' }));
    }
  };

  const handleSaveConfig = (payload) => {
    setIsSavingConfig(true);
    setSaveNotice(null);
    if (window.external && typeof window.external.sendMessage === 'function') {
      window.external.sendMessage(
        JSON.stringify({
          type: 'SAVE_API_CONFIG',
          ...payload,
        })
      );
    } else {
      setTimeout(() => {
        setIsSavingConfig(false);
        setSaveNotice({ success: true, message: 'Simulated save successful.' });
      }, 800);
    }
  };

  const handleTestKey = (provider, key) => {
    setTestStatus((prev) => ({
      ...prev,
      [provider]: { loading: true, message: 'Validating key with endpoint...' },
    }));

    if (window.external && typeof window.external.sendMessage === 'function') {
      window.external.sendMessage(
        JSON.stringify({
          type: 'TEST_API_KEY',
          provider,
          key,
        })
      );
    } else {
      setTimeout(() => {
        setTestStatus((prev) => ({
          ...prev,
          [provider]: {
            loading: false,
            success: true,
            message: 'Simulated check: Key is online (HTTP 200).',
          },
        }));
      }, 1200);
    }
  };

  const handleGetRawKey = (provider) => {
    return new Promise((resolve) => {
      rawKeyResolvers.current[provider] = resolve;
      if (window.external && typeof window.external.sendMessage === 'function') {
        window.external.sendMessage(
          JSON.stringify({
            type: 'GET_RAW_API_KEY',
            provider,
          })
        );
      } else {
        resolve('');
      }
    });
  };

  const getScoreColor = (score) => {
    if (score >= 85) return '#10b981'; // Green (Safe)
    if (score >= 50) return '#f59e0b'; // Amber (Suspicious)
    return '#ef4444'; // Red (Dangerous)
  };

  return (
    <div className="container">
      <header className="header">
        <div className="header-top">
          <div>
            <h1>URL Link Safety Checker</h1>
            <p className="subtitle">Static DOM Inspection, SSRF-Guarded Fetcher, &amp; Threat Analysis</p>
          </div>
          <button
            type="button"
            className="config-apis-btn"
            onClick={openConfigModal}
            title="Configure Threat Intelligence & Antivirus APIs"
          >
            <svg
              className="gear-icon"
              viewBox="0 0 24 24"
              width="18"
              height="18"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
              />
              <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
            <span>Configure APIs</span>
          </button>
        </div>
      </header>

      {/* Input Form */}
      <form onSubmit={handleCheck} className="input-group">
        <input
          type="text"
          id="url-input"
          className="url-input"
          placeholder="Enter URL to inspect (e.g., https://example.com)"
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            if (error) setError('');
          }}
          disabled={isLoading}
          autoFocus
        />
        <button
          type="submit"
          id="check-button"
          className="check-btn"
          disabled={isLoading || !url.trim() || !urlValidation.valid}
        >
          {isLoading ? 'Checking...' : 'Check Link'}
        </button>
        {url && (
          <button
            type="button"
            className="clear-btn"
            onClick={() => {
              setUrl('');
              setResult(null);
              setError('');
            }}
            disabled={isLoading}
          >
            Clear
          </button>
        )}
      </form>

      {/* Real-time Validation Warning */}
      {url.trim().length > 0 && !urlValidation.valid && !isLoading && (
        <div className="validation-warning">
          <svg viewBox="0 0 20 20" width="16" height="16" fill="currentColor">
            <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
          <span>{urlValidation.message}</span>
        </div>
      )}

      {/* Status / Loading indicator */}
      {isLoading && (
        <div className="status-box">
          <span className="spinner"></span>
          <span className="status-text">{statusText || 'Analyzing DOM and verifying safety signatures...'}</span>
        </div>
      )}

      {/* Error Message */}
      {error && !isLoading && (
        <div className="error-box">
          <strong>Notice: </strong> {error}
        </div>
      )}

      {/* Analysis Results Display Area */}
      {result && (
        <div className="results-container">
          {/* Safety Score Banner */}
          <div
            className="score-card"
            style={{ borderColor: getScoreColor(result.safetyScore?.score ?? 100) }}
          >
            <div className="score-header">
              <div>
                <span className="score-title">Final Safety Score</span>
                <div
                  className="score-number"
                  style={{ color: getScoreColor(result.safetyScore?.score ?? 100) }}
                >
                  {result.safetyScore?.score ?? 0}
                  <span className="score-scale">/ 100</span>
                </div>
              </div>
              <div
                className="score-badge"
                style={{ backgroundColor: getScoreColor(result.safetyScore?.score ?? 100) }}
              >
                {result.safetyScore?.rating?.toUpperCase() || 'UNKNOWN'}
              </div>
            </div>

            <p className="score-summary">{result.safetyScore?.summary}</p>

            {/* Score Deductions Breakdown */}
            {result.safetyScore?.deductions?.length > 0 && (
              <div className="deductions-list">
                <h4>Score Deductions:</h4>
                <ul>
                  {result.safetyScore.deductions.map((d, idx) => (
                    <li key={idx}>
                      <span className="deduction-penalty">-{d.pointsDeducted} pts</span>
                      <span className="deduction-reason">{d.reason}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Section 1: DOM Inspection Findings */}
          <section className="result-section">
            <h3>Automated DOM Inspection</h3>
            <div className="stats-grid">
              <div className="stat-item">
                <span className="stat-label">Anchors Scanned:</span>
                <span className="stat-value">{result.domInspection?.totalAnchorsScanned ?? 0}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Deceptive Anchors:</span>
                <span
                  className="stat-value"
                  style={{
                    color: (result.domInspection?.deceptiveAnchorsFound ?? 0) > 0 ? '#ef4444' : '#10b981',
                  }}
                >
                  {result.domInspection?.deceptiveAnchorsFound ?? 0}
                </span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Forms Scanned:</span>
                <span className="stat-value">{result.domInspection?.totalFormsScanned ?? 0}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Risky/Phishing Forms:</span>
                <span
                  className="stat-value"
                  style={{
                    color: (result.domInspection?.riskyFormsFound ?? 0) > 0 ? '#ef4444' : '#10b981',
                  }}
                >
                  {result.domInspection?.riskyFormsFound ?? 0}
                </span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Hidden IFrames:</span>
                <span
                  className="stat-value"
                  style={{
                    color: (result.domInspection?.hiddenIframesFound ?? 0) > 0 ? '#ef4444' : '#10b981',
                  }}
                >
                  {result.domInspection?.hiddenIframesFound ?? 0}
                </span>
              </div>
            </div>

            {/* Detailed DOM Warnings */}
            {result.domInspection?.findings?.length > 0 ? (
              <div className="warnings-list">
                <h4>DOM Findings &amp; Warnings:</h4>
                {result.domInspection.findings.map((finding, idx) => (
                  <div key={idx} className="warning-card">
                    <div className="warning-header">
                      <span className="warning-badge severity-badge">{finding.severity}</span>
                      <span className="warning-title">{finding.title}</span>
                    </div>
                    <p className="warning-desc">{finding.description}</p>
                    {finding.targetUrl && (
                      <div className="finding-meta">
                        <strong>Target: </strong>
                        <code>{finding.targetUrl}</code>
                      </div>
                    )}
                    {finding.elementSnippet && (
                      <pre className="element-snippet">{finding.elementSnippet}</pre>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="clean-notice">No deceptive links, phishing forms, or hidden iframes found.</p>
            )}
          </section>

          {/* Section 2: URL & Heuristic Analysis */}
          <section className="result-section">
            <h3>URL Heuristics &amp; Network Metadata</h3>
            <div className="info-list">
              <div className="info-row">
                <span className="info-key">Final URL:</span>
                <span className="info-val"><code>{result.finalUrl || result.originalUrl}</code></span>
              </div>
              <div className="info-row">
                <span className="info-key">HTTP Status:</span>
                <span className="info-val">{result.statusCode || 'N/A'}</span>
              </div>
              <div className="info-row">
                <span className="info-key">Content Size:</span>
                <span className="info-val">
                  {result.contentSizeBytes > 0 ? `${(result.contentSizeBytes / 1024).toFixed(1)} KB` : 'N/A'}
                </span>
              </div>
              <div className="info-row">
                <span className="info-key">Punycode / Homoglyph:</span>
                <span className="info-val">
                  {result.heuristics?.isPunycodeOrHomoglyph ? 'YES (Suspicious)' : 'No'}
                </span>
              </div>
              <div className="info-row">
                <span className="info-key">Raw IP Host:</span>
                <span className="info-val">
                  {result.heuristics?.isRawIpHost ? 'YES (Numerical IP)' : 'No'}
                </span>
              </div>
              <div className="info-row">
                <span className="info-key">High-Risk TLD:</span>
                <span className="info-val">
                  {result.heuristics?.hasSuspiciousTld ? 'YES (High-Abuse TLD)' : 'No'}
                </span>
              </div>
              {result.redirectChain?.length > 1 && (
                <div className="info-row full-width">
                  <span className="info-key">Redirect Chain ({result.redirectChain.length} hops):</span>
                  <ol className="redirect-list">
                    {result.redirectChain.map((hop, idx) => (
                      <li key={idx}><code>{hop}</code></li>
                    ))}
                  </ol>
                </div>
              )}
            </div>
            {result.heuristics?.warnings?.length > 0 && (
              <div className="warnings-list">
                <h4>Heuristic Warnings:</h4>
                <ul>
                  {result.heuristics.warnings.map((w, idx) => (
                    <li key={idx} className="warning-text">{w}</li>
                  ))}
                </ul>
              </div>
            )}
          </section>

          {/* Section 3: External Reputation & WHOIS */}
          <section className="result-section">
            <h3>External Reputation &amp; Intelligence</h3>
            <div className="reputation-grid">
              {result.reputationResults?.map((rep, idx) => (
                <div key={idx} className="reputation-card">
                  <div className="rep-header">
                    <strong>{rep.providerName}</strong>
                    <span
                      className="rep-status-badge"
                      style={{
                        backgroundColor: !rep.isChecked
                          ? '#475569'
                          : rep.threatType === 'UNKNOWN'
                          ? '#64748b'
                          : rep.isMalicious
                          ? '#ef4444'
                          : '#10b981',
                      }}
                    >
                      {!rep.isChecked
                        ? 'NOT CONFIGURED'
                        : rep.threatType === 'UNKNOWN'
                        ? 'UNKNOWN'
                        : rep.isMalicious
                        ? 'THREAT DETECTED'
                        : 'CLEAN'}
                    </span>
                  </div>
                  <p className="rep-msg">{rep.statusMessage}</p>
                  {rep.details && Object.keys(rep.details).length > 0 && (
                    <div className="rep-details">
                      {Object.entries(rep.details).map(([k, v]) => (
                        <div key={k} className="rep-detail-row">
                          <span className="rep-detail-key">{k}: </span>
                          <span className="rep-detail-val">{v}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>
        </div>
      )}

      {/* In-App API Configuration Modal */}
      <ApiConfigModal
        isOpen={isConfigModalOpen}
        onClose={() => setIsConfigModalOpen(false)}
        config={apiConfig}
        onSave={handleSaveConfig}
        onTest={handleTestKey}
        onGetRawKey={handleGetRawKey}
        testStatus={testStatus}
        isSaving={isSavingConfig}
        saveNotice={saveNotice}
      />
    </div>
  );
}
