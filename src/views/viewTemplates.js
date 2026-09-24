function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function renderBotShieldPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secure Handover</title>
  <link rel="stylesheet" href="/css/style.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
</head>
<body>
  <div class="cyber-grid-bg"></div>
  <div class="glow-orb glow-orb-1"></div>
  <div class="glow-orb glow-orb-2"></div>

  <div class="container">
    <header class="app-header">
      <div class="brand-badge">
        <span class="status-dot"></span>
        <span class="badge-text">AIR-GAPPED PROTOCOL</span>
      </div>
    </header>

    <main class="main-card" style="text-align: center;">
      <div class="card-header">
        <div class="shield-icon-wrapper" style="margin: 0 auto 16px auto;">
          <svg class="shield-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>
        <h1 class="main-heading">Secure Handover</h1>
        <p class="description" style="margin-top: 12px;">Human verification required to access this secure handover.</p>
      </div>
    </main>

    <footer class="app-footer">
      <p>VaultLink Protocol &bull; Zero-Knowledge Handover Pipeline</p>
    </footer>
  </div>
</body>
</html>`;
}

function renderUnavailablePage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secure Handover Unavailable</title>
  <link rel="stylesheet" href="/css/style.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
</head>
<body>
  <div class="cyber-grid-bg"></div>
  <div class="glow-orb glow-orb-1"></div>
  <div class="glow-orb glow-orb-2"></div>

  <div class="container">
    <header class="app-header">
      <div class="brand-badge">
        <span class="status-dot" style="background-color: var(--accent-danger); box-shadow: 0 0 8px var(--accent-danger);"></span>
        <span class="badge-text" style="color: #f87171;">HANDOVER UNAVAILABLE</span>
      </div>
    </header>

    <main class="main-card" style="text-align: center;">
      <div class="card-header">
        <div class="shield-icon-wrapper" style="border-color: rgba(239, 68, 68, 0.3); background: linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(245, 158, 11, 0.1)); margin: 0 auto 16px auto;">
          <svg class="shield-icon" style="color: #f87171;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <line x1="15" y1="9" x2="9" y2="15"/>
            <line x1="9" y1="9" x2="15" y2="15"/>
          </svg>
        </div>
        <h1 class="main-heading">Secure Handover Unavailable</h1>
        <p class="description" style="margin-top: 14px; margin-bottom: 24px;">
          This secure handover is unavailable, expired, or has already been destroyed.
        </p>
        <div class="action-footer">
          <a href="/" class="submit-btn" style="text-decoration: none; display: inline-flex; width: auto; padding: 12px 28px;">
            Return to VaultLink
          </a>
        </div>
      </div>
    </main>

    <footer class="app-footer">
      <p>VaultLink Protocol &bull; Zero-Knowledge Handover Pipeline</p>
    </footer>
  </div>
</body>
</html>`;
}

function renderActivePage(metadata) {
  const safeId = escapeHtml(metadata.id);
  const safeExpires = escapeHtml(metadata.expires_at);
  const safeAvailable = escapeHtml(metadata.available_at);
  const safeViews = parseInt(metadata.views_remaining, 10) || 1;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VaultLink - Secure Handover</title>
  <link rel="stylesheet" href="/css/style.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
</head>
<body>
  <div class="cyber-grid-bg"></div>
  <div class="glow-orb glow-orb-1"></div>
  <div class="glow-orb glow-orb-2"></div>

  <div class="container">
    <header class="app-header">
      <div class="brand-badge">
        <span class="status-dot"></span>
        <span class="badge-text">SECURE RECEIVER ROOM</span>
      </div>
    </header>

    <main class="main-card">
      <div class="card-header">
        <div class="shield-icon-wrapper">
          <svg class="shield-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>
        <h1 class="main-heading">You have received a secure handover</h1>
        <p class="description">
          Verify your secure handover details to reveal this secret.
        </p>
        <p class="description availability-notice" style="margin-top: 6px; color: var(--accent-cyan); font-weight: 500;">
          This secure handover is now available for verification.
        </p>
        <div class="status-badge-container">
          <span class="status-badge active">Active</span>
        </div>
      </div>

      <!-- Expiry Countdown Card -->
      <div class="countdown-card">
        <div class="countdown-header">
          <span class="countdown-label">Expiry Countdown</span>
          <span id="countdown-display" class="countdown-timer mono">--:--:--</span>
        </div>
      </div>

      <!-- Safe Metadata Box -->
      <div class="details-box" style="margin-bottom: 20px;">
        <div class="detail-item">
          <span class="detail-key">Expiry date/time</span>
          <span id="expiry-formatted" class="detail-val mono">${safeExpires}</span>
        </div>
        <div class="detail-item">
          <span class="detail-key">Views remaining</span>
          <span class="detail-val mono">${safeViews}</span>
        </div>
      </div>

      <!-- Error Alert Banner -->
      <div id="verify-error-banner" class="alert-banner error-banner hidden" role="alert">
        <span class="alert-icon">⚠️</span>
        <span id="verify-error-text" class="alert-msg">Verification failed. Please check your secure handover details.</span>
      </div>

      <!-- Verification Form -->
      <form id="recipient-form" class="secret-form" novalidate autocomplete="off">
        <div class="form-group">
          <label for="access-code-input" class="form-label">Access Code <span class="required">*</span></label>
          <input
            type="text"
            id="access-code-input"
            name="access_code"
            class="form-input mono"
            placeholder="Enter 6-digit access code"
            maxlength="6"
            inputmode="numeric"
            pattern="[0-9]{6}"
            autocomplete="off"
            required
          >
          <span class="helper-text">Enter the 6-digit PIN provided by the sender.</span>
        </div>

        <div class="form-group">
          <label for="passphrase-input" class="form-label">Passphrase <span class="required">*</span></label>
          <div class="input-with-action">
            <input
              type="password"
              id="passphrase-input"
              name="passphrase"
              class="form-input"
              placeholder="Enter secret passphrase"
              autocomplete="new-password"
              required
            >
            <button type="button" id="toggle-passphrase-btn" class="input-action-btn" aria-label="Toggle passphrase visibility">
              <svg id="eye-icon" class="action-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                <circle cx="12" cy="12" r="3"/>
              </svg>
            </button>
          </div>
          <span class="helper-text">Enter the passphrase provided by the sender.</span>
        </div>

        <button type="submit" id="verify-btn" class="submit-btn">
          <span class="btn-spinner hidden" id="verify-spinner"></span>
          <span class="btn-text" id="verify-btn-text">Verify Secure Handover</span>
        </button>
      </form>

      <!-- Verified Success State (Step 7) -->
      <div id="verified-section" class="verified-section hidden">
        <div class="verified-success-box">
          <div class="verified-icon-row">
            <span class="verified-icon">🛡️</span>
            <span class="verified-title">Verification Successful</span>
          </div>
          <p class="verified-desc">Identity verified. You may now reveal and destroy the secret.</p>
        </div>

        <button type="button" id="reveal-btn" class="submit-btn reveal-btn" style="margin-top: 16px;">
          <span class="btn-spinner hidden" id="reveal-spinner"></span>
          <span class="btn-text" id="reveal-btn-text">Reveal & Destroy Secret</span>
        </button>
      </div>

      <!-- Reveal Panel (Step 8 & 11) -->
      <div id="reveal-panel" class="reveal-panel hidden">
        <div class="card-header" style="margin-bottom: 16px;">
          <div class="success-icon-wrapper">
            <svg class="success-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="20 6 9 17 4 12"/>
            </svg>
          </div>
          <h2 class="main-heading success-heading">Secret Revealed</h2>
        </div>

        <!-- Active Secret Container (wiped after 15 seconds) -->
        <div id="secret-active-box">
          <!-- 15-Second Warning Banner -->
          <div class="alert-banner warning-banner" style="margin-bottom: 16px;">
            <span class="alert-icon">⏳</span>
            <span class="alert-msg">Copy this secret now. This secret will clear in <strong id="reveal-countdown-num">15</strong> seconds.</span>
          </div>

          <!-- Visual Countdown Progress Bar -->
          <div class="reveal-progress-container">
            <div id="reveal-progress-bar" class="reveal-progress-fill"></div>
          </div>

          <!-- Protected Secret Display -->
          <div class="form-group" style="margin-top: 16px;">
            <label class="form-label">Decrypted Secret</label>
            <textarea id="revealed-secret-text" class="form-textarea mono secret-output" rows="4" readonly spellcheck="false"></textarea>
          </div>

          <!-- Copy Action Button -->
          <button type="button" id="copy-secret-btn" class="submit-btn" style="margin-top: 14px;">
            <span class="copy-icon">📋</span>
            <span id="copy-secret-btn-text">Copy Secret</span>
          </button>
        </div>

        <!-- Secret Erased / Destroyed Box (shown after 15 seconds) -->
        <div id="secret-erased-box" class="hidden" style="text-align: center; padding: 18px 0; margin-bottom: 8px;">
          <div class="shield-icon-wrapper" style="border-color: rgba(239, 68, 68, 0.3); background: linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(245, 158, 11, 0.1)); margin: 0 auto 12px auto;">
            <svg class="shield-icon" style="color: #f87171;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <line x1="15" y1="9" x2="9" y2="15"/>
              <line x1="9" y1="9" x2="15" y2="15"/>
            </svg>
          </div>
          <h3 class="main-heading" style="font-size: 1.35rem; color: #f87171; margin-bottom: 6px;">Secret Destroyed</h3>
          <p class="description" style="margin-bottom: 0;">This secret has been permanently destroyed.</p>
        </div>

        <!-- Recipient Acknowledgement Panel (Step 11) -->
        <div id="ack-section" class="ack-section" style="margin-top: 24px; padding-top: 20px; border-top: 1px solid rgba(255, 255, 255, 0.1); text-align: left;">
          <div class="ack-card" style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 10px; padding: 18px;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
              <span style="font-weight: 600; font-size: 0.95rem; color: #f1f5f9; display: flex; align-items: center; gap: 8px;">
                <span>📬</span> Confirm Handover Receipt
              </span>
              <span id="ack-countdown-badge" class="badge-text" style="font-size: 0.75rem; color: #94a3b8; background: rgba(148, 163, 184, 0.1); padding: 2px 8px; border-radius: 4px;">15m window</span>
            </div>
            
            <div id="ack-controls">
              <label class="custom-checkbox-container" style="display: flex; align-items: flex-start; gap: 10px; cursor: pointer; user-select: none;">
                <input type="checkbox" id="ack-checkbox" style="margin-top: 3px; width: 16px; height: 16px; accent-color: var(--accent-cyan, #00d2ff); cursor: pointer;">
                <span style="font-size: 0.88rem; color: #cbd5e1; line-height: 1.4;">
                  I have copied and understood this secure handover.
                </span>
              </label>

              <button type="button" id="acknowledge-btn" class="submit-btn" disabled style="margin-top: 14px; width: 100%; opacity: 0.5;">
                <span class="btn-spinner hidden" id="ack-spinner"></span>
                <span id="ack-btn-text">Acknowledge Receipt</span>
              </button>
            </div>

            <!-- Acknowledgement Success Confirmation -->
            <div id="ack-success-box" class="hidden" style="margin-top: 12px; padding: 12px; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 6px; color: #34d399; font-size: 0.88rem; text-align: center; font-weight: 500;">
              Receipt acknowledged. The sender has been notified.
            </div>

            <!-- Acknowledgement Window Expired Notice -->
            <div id="ack-expired-box" class="hidden" style="margin-top: 12px; padding: 12px; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 6px; color: #f87171; font-size: 0.88rem; text-align: center;">
              Acknowledgement window has expired.
            </div>
          </div>
        </div>
      </div>

      <!-- Permanently Destroyed State Panel -->
      <div id="destroyed-panel" class="destroyed-panel hidden" style="text-align: center;">
        <div class="shield-icon-wrapper" style="border-color: rgba(239, 68, 68, 0.3); background: linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(245, 158, 11, 0.1)); margin: 0 auto 16px auto;">
          <svg class="shield-icon" style="color: #f87171;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <line x1="15" y1="9" x2="9" y2="15"/>
            <line x1="9" y1="9" x2="15" y2="15"/>
          </svg>
        </div>
        <h2 class="main-heading" style="font-size: 1.6rem; color: #f87171;">Secret Destroyed</h2>
        <p class="description" style="margin-top: 12px; margin-bottom: 24px;">
          This secret has been permanently destroyed.
        </p>
        <div class="action-footer">
          <a href="/" class="submit-btn" style="text-decoration: none; display: inline-flex; width: auto; padding: 12px 28px;">
            Return to VaultLink
          </a>
        </div>
      </div>

      <!-- Security Policy Advisory -->
      <div class="security-advisory-card" style="margin-top: 20px;">
        <div class="advisory-title">
          <span>🛡️</span>
          <strong>Security Handover Policy</strong>
        </div>
        <p class="advisory-text">
          This secret will be revealed only after verification and can be accessed only once.
        </p>
      </div>
    </main>

    <footer class="app-footer">
      <p>VaultLink Protocol &bull; Zero-Knowledge Handover Pipeline</p>
    </footer>
  </div>

  <div id="handover-meta"
       data-id="${safeId}"
       data-status="active"
       data-expires-at="${safeExpires}"
       data-available-at="${safeAvailable}"
       data-views-remaining="${safeViews}"
       style="display: none;"></div>

  <script src="/js/view.js"></script>
</body>
</html>`;
}

function renderScheduledPage(metadata) {
  const safeId = escapeHtml(metadata.id);
  const safeExpires = escapeHtml(metadata.expires_at);
  const safeAvailable = escapeHtml(metadata.available_at);
  const safeViews = parseInt(metadata.views_remaining, 10) || 1;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VaultLink - Secure Handover Scheduled</title>
  <link rel="stylesheet" href="/css/style.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
</head>
<body>
  <div class="cyber-grid-bg"></div>
  <div class="glow-orb glow-orb-1"></div>
  <div class="glow-orb glow-orb-2"></div>

  <div class="container">
    <header class="app-header">
      <div class="brand-badge">
        <span class="status-dot" style="background-color: var(--accent-amber); box-shadow: 0 0 8px var(--accent-amber);"></span>
        <span class="badge-text" style="color: #fbbf24;">TIMELOCKED PROTOCOL</span>
      </div>
    </header>

    <main class="main-card">
      <div class="card-header">
        <div class="shield-icon-wrapper" style="border-color: rgba(245, 158, 11, 0.3); background: linear-gradient(135deg, rgba(245, 158, 11, 0.15), rgba(217, 119, 6, 0.1));">
          <svg class="shield-icon" style="color: #fbbf24;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>
        <h1 class="main-heading">Secure Handover Scheduled</h1>
        <p class="description">
          This handover is not available yet.
        </p>
        <div class="status-badge-container">
          <span class="status-badge scheduled">Scheduled</span>
        </div>
      </div>

      <!-- Scheduled Unlock Countdown -->
      <div class="countdown-card scheduled">
        <div class="countdown-header">
          <span class="countdown-label">Scheduled Unlock Countdown</span>
          <span id="countdown-display" class="countdown-timer mono scheduled-timer">--:--:--</span>
        </div>
      </div>

      <!-- Metadata Box -->
      <div class="details-box" style="margin-bottom: 20px;">
        <div class="detail-item">
          <span class="detail-key">Scheduled unlock date/time</span>
          <span id="available-formatted" class="detail-val mono highlight">${safeAvailable}</span>
        </div>
        <div class="detail-item">
          <span class="detail-key">Expiry date/time</span>
          <span id="expiry-formatted" class="detail-val mono">${safeExpires}</span>
        </div>
      </div>

      <!-- Disabled Form -->
      <form id="recipient-form" class="secret-form" novalidate autocomplete="off" onsubmit="return false;">
        <div class="form-group">
          <label for="access-code-input" class="form-label">Access Code</label>
          <input
            type="text"
            id="access-code-input"
            name="access_code"
            class="form-input mono"
            placeholder="Enter 6-digit access code"
            disabled
          >
        </div>

        <div class="form-group">
          <label for="passphrase-input" class="form-label">Passphrase</label>
          <input
            type="password"
            id="passphrase-input"
            name="passphrase"
            class="form-input"
            placeholder="Enter secret passphrase"
            disabled
          >
        </div>

        <button type="button" id="verify-btn" class="submit-btn" disabled>
          <span class="btn-text">Verify Secure Handover</span>
        </button>
      </form>

      <!-- Scheduled Advisory -->
      <div class="security-advisory-card" style="margin-top: 20px; border-color: rgba(245, 158, 11, 0.3);">
        <div class="advisory-title">
          <span>⏳</span>
          <strong>Scheduled Transmission</strong>
        </div>
        <p class="advisory-text">
          Access becomes available automatically at the scheduled time.
        </p>
      </div>
    </main>

    <footer class="app-footer">
      <p>VaultLink Protocol &bull; Zero-Knowledge Handover Pipeline</p>
    </footer>
  </div>

  <div id="handover-meta"
       data-id="${safeId}"
       data-status="scheduled"
       data-expires-at="${safeExpires}"
       data-available-at="${safeAvailable}"
       data-views-remaining="${safeViews}"
       style="display: none;"></div>

  <script src="/js/view.js"></script>
</body>
</html>`;
}

function formatUtcDate(isoStr) {
  if (!isoStr) return '--';
  try {
    const d = new Date(isoStr);
    return d.toUTCString().replace('GMT', 'UTC');
  } catch {
    return isoStr;
  }
}

function getStatusMessage(status) {
  switch (status) {
    case 'scheduled':
      return 'The handover will activate at the scheduled time.';
    case 'active':
      return 'This handover remains available until it expires, is revealed, or is revoked.';
    case 'burned':
      return 'The secret was revealed and encrypted data has been permanently removed.';
    case 'expired':
      return 'The handover expired and encrypted data has been removed.';
    case 'revoked':
      return 'The sender permanently revoked this handover.';
    case 'revealed':
      return 'The secret was revealed and encrypted data has been permanently removed.';
    case 'acknowledged':
      return 'The recipient acknowledged receipt of this secret.';
    default:
      return 'This handover is currently inactive.';
  }
}

function formatEventType(type) {
  switch (type) {
    case 'created':
      return 'Created';
    case 'scheduled':
      return 'Scheduled';
    case 'activated':
      return 'Activated';
    case 'verification_passed':
      return 'Verification passed';
    case 'revealed':
      return 'Revealed';
    case 'expired':
      return 'Expired';
    case 'panic_burned':
    case 'revoked':
      return 'Revoked';
    case 'acknowledged':
      return 'Acknowledged';
    default:
      return type ? type.replace(/_/g, ' ') : 'Event';
  }
}

function renderDashboardPage({ secret, events = [], csrfToken = '' }) {
  const safeId = escapeHtml(secret.id);
  const safeStatus = escapeHtml(secret.status || 'unknown');
  const safeCreatedAt = formatUtcDate(secret.created_at);
  const safeAvailableAt = formatUtcDate(secret.available_at);
  const safeExpiresAt = formatUtcDate(secret.expires_at);
  const safeMaxViews = parseInt(secret.max_views, 10) || 1;
  const safeViewsRemaining = parseInt(secret.views_remaining, 10) || 0;
  const safeRevealedAt = secret.revealed_at ? formatUtcDate(secret.revealed_at) : null;
  const safeAcknowledgedAt = secret.acknowledged_at ? formatUtcDate(secret.acknowledged_at) : null;
  const safeRevokedAt = secret.revoked_at ? formatUtcDate(secret.revoked_at) : null;

  let ackStatusText = '';
  let ackBadgeLabel = '';
  if (secret.acknowledged_at) {
    ackStatusText = `Acknowledged at: ${safeAcknowledgedAt}`;
    ackBadgeLabel = 'Confirmed';
  } else if (secret.revealed_at || secret.status === 'revealed' || secret.status === 'burned') {
    ackStatusText = 'Acknowledgement pending';
    ackBadgeLabel = 'Pending';
  } else {
    ackStatusText = 'Not applicable until reveal';
    ackBadgeLabel = 'N/A';
  }

  const statusLabel = safeStatus.charAt(0).toUpperCase() + safeStatus.slice(1);
  const statusMessage = getStatusMessage(secret.status);
  const canPanicBurn = secret.status === 'scheduled' || secret.status === 'active';

  const timelineHtml = events.length === 0
    ? `<div class="timeline-empty">No activity recorded yet.</div>`
    : events.map((ev) => {
        const evType = formatEventType(ev.event_type);
        const evTime = formatUtcDate(ev.created_at);
        return `
          <div class="timeline-item">
            <div class="timeline-dot"></div>
            <div class="timeline-content">
              <span class="timeline-title">${escapeHtml(evType)}</span>
              <span class="timeline-time mono">${escapeHtml(evTime)}</span>
            </div>
          </div>
        `;
      }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secure Handover Management - VaultLink</title>
  <link rel="stylesheet" href="/css/style.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
</head>
<body>
  <div class="cyber-grid-bg"></div>
  <div class="glow-orb glow-orb-1"></div>
  <div class="glow-orb glow-orb-2"></div>

  <div class="container">
    <header class="app-header">
      <div class="brand-badge">
        <span class="status-dot"></span>
        <span class="badge-text">SENDER MANAGEMENT CONSOLE</span>
      </div>
    </header>

    <main class="main-card">
      <div class="card-header">
        <div class="shield-icon-wrapper" style="border-color: rgba(56, 189, 248, 0.35); background: linear-gradient(135deg, rgba(0, 210, 255, 0.15), rgba(56, 189, 248, 0.1));">
          <svg class="shield-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>
        <h1 class="main-heading">Secure Handover Management</h1>
        <p class="description">
          Monitor safe lifecycle telemetry and manage secret access.
        </p>
        <div class="status-badge-container">
          <span id="dashboard-status-badge" class="status-badge ${safeStatus}">${statusLabel}</span>
        </div>
      </div>

      <!-- Status-Specific Advisory Message -->
      <div class="details-box" style="margin-bottom: 20px; text-align: center; padding: 14px;">
        <p id="dashboard-status-message" class="description" style="color: var(--text-primary); font-weight: 500; margin: 0 auto;">
          ${statusMessage}
        </p>
      </div>

      <!-- Privacy Warning Advisory -->
      <div class="security-advisory-card" style="margin-bottom: 20px;">
        <div class="advisory-title">
          <span>🛡️</span>
          <strong>Zero-Knowledge Privacy Guarantee</strong>
        </div>
        <p class="advisory-text">
          This dashboard never displays the secret or recipient credentials.
        </p>
      </div>

      <!-- Alert Banners -->
      <div id="dashboard-success-banner" class="alert-banner info-banner hidden" role="alert">
        <span class="alert-icon">✓</span>
        <span id="dashboard-success-text" class="alert-msg">Secure handover permanently revoked.</span>
      </div>
      <div id="dashboard-error-banner" class="alert-banner error-banner hidden" role="alert">
        <span class="alert-icon">⚠️</span>
        <span id="dashboard-error-text" class="alert-msg">Secure handover unavailable.</span>
      </div>

      <!-- Metadata Cards Grid -->
      <div class="details-box" style="margin-bottom: 24px;">
        <div class="detail-item">
          <span class="detail-key">Handover ID</span>
          <span class="detail-val mono" style="font-size: 0.8rem;">${safeId}</span>
        </div>
        <div class="detail-item">
          <span class="detail-key">Created at</span>
          <span class="detail-val mono">${safeCreatedAt}</span>
        </div>
        <div class="detail-item">
          <span class="detail-key">Scheduled unlock time</span>
          <span class="detail-val mono highlight">${safeAvailableAt}</span>
        </div>
        <div class="detail-item">
          <span class="detail-key">Expiry time</span>
          <span class="detail-val mono">${safeExpiresAt}</span>
        </div>
        <div class="detail-item">
          <span class="detail-key">Maximum views</span>
          <span class="detail-val mono">${safeMaxViews}</span>
        </div>
        <div class="detail-item">
          <span class="detail-key">Remaining views</span>
          <span id="dashboard-views-remaining" class="detail-val mono">${safeViewsRemaining}</span>
        </div>
        ${safeRevealedAt ? `
        <div class="detail-item">
          <span class="detail-key">Revealed at</span>
          <span class="detail-val mono">${safeRevealedAt}</span>
        </div>` : ''}
        ${safeAcknowledgedAt ? `
        <div class="detail-item">
          <span class="detail-key">Acknowledged at</span>
          <span class="detail-val mono">${safeAcknowledgedAt}</span>
        </div>` : ''}
        <div id="revoked-at-row" class="detail-item ${safeRevokedAt ? '' : 'hidden'}">
          <span class="detail-key">Revoked at</span>
          <span id="dashboard-revoked-at" class="detail-val mono" style="color: #f87171;">${safeRevokedAt || '--'}</span>
        </div>
      </div>

      <!-- Recipient Acknowledgement Card (Step 11) -->
      <div class="details-box" style="margin-bottom: 24px; padding: 18px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <span style="font-weight: 600; font-size: 0.95rem; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
            <span>📬</span> Recipient acknowledgement
          </span>
          <span class="status-badge" style="font-size: 0.72rem; padding: 3px 10px; ${secret.acknowledged_at ? 'background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4);' : (secret.revealed_at || secret.status === 'revealed' || secret.status === 'burned' ? 'background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4);' : 'background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.25);')}">
            ${ackBadgeLabel}
          </span>
        </div>
        <div class="detail-val mono" style="font-size: 0.9rem; color: ${secret.acknowledged_at ? '#34d399' : 'var(--text-secondary)'};">
          ${escapeHtml(ackStatusText)}
        </div>
      </div>

      <!-- Panic Burn Action Section -->
      <div id="panic-burn-container" class="${canPanicBurn ? '' : 'hidden'}" style="margin-bottom: 24px;">
        <button type="button" id="panic-burn-btn" class="submit-btn" style="background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%); box-shadow: 0 4px 15px rgba(239, 68, 68, 0.35);">
          <span class="btn-icon">🔥</span>
          <span class="btn-text">Panic Burn Secret</span>
        </button>
      </div>

      <!-- Safe Activity Timeline -->
      <div class="timeline-container">
        <h3 class="sub-heading" style="color: var(--text-primary); font-size: 0.95rem; margin-bottom: 14px;">Safe Activity Timeline</h3>
        <div id="timeline-list" class="timeline-list">
          ${timelineHtml}
        </div>
      </div>
    </main>

    <!-- Confirmation Modal -->
    <div id="burn-modal" class="modal-backdrop hidden" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div class="modal-card">
        <div class="card-header" style="margin-bottom: 12px;">
          <div class="shield-icon-wrapper" style="border-color: rgba(239, 68, 68, 0.4); background: rgba(239, 68, 68, 0.15); margin: 0 auto 12px auto;">
            <svg class="shield-icon" style="color: #ef4444;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
          </div>
          <h3 id="modal-title" class="main-heading" style="font-size: 1.35rem; color: #f87171;">Permanently revoke this secure handover?</h3>
          <p class="description" style="margin-top: 8px;">
            This cannot be undone. The recipient will no longer be able to access this secret.
          </p>
        </div>
        <div class="modal-actions" style="display: flex; gap: 12px; margin-top: 16px;">
          <button type="button" id="modal-cancel-btn" class="secondary-action-btn" style="flex: 1; justify-content: center;">Cancel</button>
          <button type="button" id="modal-confirm-burn-btn" class="submit-btn" style="flex: 1; background: #dc2626; justify-content: center;">
            <span class="btn-spinner hidden" id="modal-spinner"></span>
            <span id="modal-confirm-text">Burn Secret Permanently</span>
          </button>
        </div>
      </div>
    </div>

    <footer class="app-footer">
      <p>VaultLink Protocol &bull; Zero-Knowledge Handover Pipeline</p>
    </footer>
  </div>

  <input type="hidden" id="csrf-token" value="${escapeHtml(csrfToken)}">
  <div id="dashboard-meta" data-id="${safeId}" data-status="${safeStatus}" style="display: none;"></div>

  <script src="/js/manage.js"></script>
</body>
</html>`;
}

module.exports = {
  renderBotShieldPage,
  renderUnavailablePage,
  renderActivePage,
  renderScheduledPage,
  renderDashboardPage
};

