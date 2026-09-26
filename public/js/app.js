/**
 * VaultLink - Secure Handover Room
 * Sender-Facing Frontend Client Application
 * Zero-Knowledge, Zero-Storage, Client-Side Validation & QR Generation
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements - Creation Section
  const creationSection = document.getElementById('creation-section');
  const successSection = document.getElementById('success-section');
  const secretForm = document.getElementById('secret-form');

  const secretInput = document.getElementById('secret-input');
  const secretCharCount = document.getElementById('secret-char-count');
  const secretError = document.getElementById('secret-error');

  const ttlSelect = document.getElementById('ttl-select');
  const ttlError = document.getElementById('ttl-error');

  const maxViewsSelect = document.getElementById('max-views-select');
  const maxViewsError = document.getElementById('max-views-error');

  const scheduleToggle = document.getElementById('schedule-toggle');
  const scheduleFieldsWrapper = document.getElementById('schedule-fields-wrapper');
  const availableAtInput = document.getElementById('available-at-input');
  const availableAtError = document.getElementById('available-at-error');

  const accessCodeInput = document.getElementById('access-code-input');
  const generateCodeBtn = document.getElementById('generate-code-btn');
  const accessCodeError = document.getElementById('access-code-error');

  const passphraseInput = document.getElementById('passphrase-input');
  const togglePassphraseBtn = document.getElementById('toggle-passphrase-btn');
  const passphraseError = document.getElementById('passphrase-error');

  const submitBtn = document.getElementById('submit-btn');
  const submitSpinner = document.getElementById('submit-spinner');
  const submitBtnText = document.getElementById('submit-btn-text');
  const formGlobalError = document.getElementById('form-global-error');

  // DOM Elements - Success Section
  const statusBadge = document.getElementById('status-badge');
  const recipientLinkInput = document.getElementById('recipient-link-input');
  const copyViewBtn = document.getElementById('copy-view-btn');
  const manageLinkInput = document.getElementById('manage-link-input');
  const copyManageBtn = document.getElementById('copy-manage-btn');
  const qrCanvas = document.getElementById('qr-canvas');

  const displayExpiresAt = document.getElementById('display-expires-at');
  const displayAvailableRow = document.getElementById('display-available-row');
  const displayAvailableAt = document.getElementById('display-available-at');
  const displayViewsRemaining = document.getElementById('display-views-remaining');
  const displayFingerprint = document.getElementById('display-fingerprint');
  const createAnotherBtn = document.getElementById('create-another-btn');

  // 1. Live Character Counter for Secret Textarea
  secretInput.addEventListener('input', () => {
    const len = secretInput.value.length;
    secretCharCount.textContent = `${len.toLocaleString()} / 10,000`;
    clearError(secretInput, secretError);
  });

  // 2. Numeric-Only Filter for Access Code
  accessCodeInput.addEventListener('input', () => {
    accessCodeInput.value = accessCodeInput.value.replace(/\D/g, '').slice(0, 6);
    clearError(accessCodeInput, accessCodeError);
  });

  // 3. Quick PIN Generator
  generateCodeBtn.addEventListener('click', () => {
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    const pin = String(100000 + (array[0] % 900000));
    accessCodeInput.value = pin;
    clearError(accessCodeInput, accessCodeError);
  });

  // 4. Passphrase Input Show/Hide Toggle
  togglePassphraseBtn.addEventListener('click', () => {
    const isPassword = passphraseInput.type === 'password';
    passphraseInput.type = isPassword ? 'text' : 'password';
    togglePassphraseBtn.innerHTML = isPassword
      ? `<svg class="action-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
          <line x1="1" y1="1" x2="23" y2="23"/>
        </svg>`
      : `<svg class="action-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
          <circle cx="12" cy="12" r="3"/>
        </svg>`;
  });

  passphraseInput.addEventListener('input', () => {
    clearError(passphraseInput, passphraseError);
  });

  // 5. Schedule Toggle Behavior & Min Timestamp Constraint
  scheduleToggle.addEventListener('change', () => {
    if (scheduleToggle.checked) {
      scheduleFieldsWrapper.classList.remove('hidden');
      updateMinScheduleTime();
    } else {
      scheduleFieldsWrapper.classList.add('hidden');
      availableAtInput.value = '';
      clearError(availableAtInput, availableAtError);
    }
  });

  function updateMinScheduleTime() {
    const now = new Date();
    // Offset to next full minute
    now.setMinutes(now.getMinutes() + 1);
    const localIso = new Date(now.getTime() - now.getTimezoneOffset() * 60000)
      .toISOString()
      .slice(0, 16);
    availableAtInput.min = localIso;
  }

  availableAtInput.addEventListener('input', () => {
    clearError(availableAtInput, availableAtError);
  });

  ttlSelect.addEventListener('change', () => clearError(ttlSelect, ttlError));
  maxViewsSelect.addEventListener('change', () => clearError(maxViewsSelect, maxViewsError));

  function clearError(inputElem, errorElem) {
    if (inputElem) inputElem.classList.remove('error');
    if (errorElem) errorElem.textContent = '';
    formGlobalError.classList.add('hidden');
  }

  function setError(inputElem, errorElem, message) {
    if (inputElem) inputElem.classList.add('error');
    if (errorElem) errorElem.textContent = message;
  }

  // 6. Form Submission Validation and API Handshake
  secretForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    formGlobalError.classList.add('hidden');

    let isValid = true;
    let firstInvalidInput = null;

    // Validate Secret
    const secretValue = secretInput.value;
    if (!secretValue || secretValue.trim().length === 0) {
      setError(secretInput, secretError, 'Please enter a secret to protect.');
      isValid = false;
      if (!firstInvalidInput) firstInvalidInput = secretInput;
    } else if (secretValue.length > 10000) {
      setError(secretInput, secretError, 'Secret payload exceeds 10,000 characters limit.');
      isValid = false;
      if (!firstInvalidInput) firstInvalidInput = secretInput;
    }

    // Validate TTL
    const ttlSeconds = parseInt(ttlSelect.value, 10);
    if (isNaN(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 86400) {
      setError(ttlSelect, ttlError, 'Please select a valid expiration window.');
      isValid = false;
      if (!firstInvalidInput) firstInvalidInput = ttlSelect;
    }

    // Validate Max Views
    const maxViews = parseInt(maxViewsSelect.value, 10);
    if (isNaN(maxViews) || maxViews < 1 || maxViews > 5) {
      setError(maxViewsSelect, maxViewsError, 'Please select valid reveal attempts (1-5).');
      isValid = false;
      if (!firstInvalidInput) firstInvalidInput = maxViewsSelect;
    }

    // Validate Schedule
    let availableAtIso = undefined;
    if (scheduleToggle.checked) {
      const scheduleVal = availableAtInput.value;
      if (!scheduleVal) {
        setError(availableAtInput, availableAtError, 'Please select a release date & time.');
        isValid = false;
        if (!firstInvalidInput) firstInvalidInput = availableAtInput;
      } else {
        const scheduleDate = new Date(scheduleVal);
        const now = new Date();
        if (isNaN(scheduleDate.getTime()) || scheduleDate.getTime() < now.getTime()) {
          setError(availableAtInput, availableAtError, 'Scheduled time must be in the future.');
          isValid = false;
          if (!firstInvalidInput) firstInvalidInput = availableAtInput;
        } else {
          availableAtIso = scheduleDate.toISOString();
        }
      }
    }

    // Validate Access Code
    const accessCodeValue = accessCodeInput.value.trim();
    if (!/^\d{6}$/.test(accessCodeValue)) {
      setError(accessCodeInput, accessCodeError, 'Access code must be exactly 6 numeric digits.');
      isValid = false;
      if (!firstInvalidInput) firstInvalidInput = accessCodeInput;
    }

    // Validate Passphrase
    const passphraseValue = passphraseInput.value;
    if (!passphraseValue || passphraseValue.length < 8) {
      setError(passphraseInput, passphraseError, 'Passphrase must be at least 8 characters long.');
      isValid = false;
      if (!firstInvalidInput) firstInvalidInput = passphraseInput;
    } else if (passphraseValue.length > 128) {
      setError(passphraseInput, passphraseError, 'Passphrase cannot exceed 128 characters.');
      isValid = false;
      if (!firstInvalidInput) firstInvalidInput = passphraseInput;
    }

    if (!isValid) {
      if (firstInvalidInput) firstInvalidInput.focus();
      return;
    }

    // Build Request Payload
    const payload = {
      secret: secretValue,
      ttl_seconds: ttlSeconds,
      max_views: maxViews,
      access_code: accessCodeValue,
      passphrase: passphraseValue
    };

    if (availableAtIso) {
      payload.available_at = availableAtIso;
    }

    // Set UI Loading State
    setSubmitting(true);

    try {
      const response = await fetch('/api/secrets', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      const data = await response.json();

      if (!response.ok || !data || !data.id) {
        throw new Error(data && data.error ? data.error : 'Creation failed');
      }

      // Zero-Knowledge Hygiene: Wipe secret content from memory and DOM immediately
      secretInput.value = '';
      passphraseInput.value = '';
      accessCodeInput.value = '';
      secretCharCount.textContent = '0 / 10,000';

      // Display Success Panel
      displaySuccessHandover(data);
    } catch (err) {
      formGlobalError.classList.remove('hidden');
      formGlobalError.scrollIntoView({ behavior: 'smooth', block: 'center' });
    } finally {
      setSubmitting(false);
    }
  });

  function setSubmitting(isSubmitting) {
    submitBtn.disabled = isSubmitting;
    if (isSubmitting) {
      submitSpinner.classList.remove('hidden');
      submitBtnText.textContent = 'Encrypting & Generating Link...';
    } else {
      submitSpinner.classList.add('hidden');
      submitBtnText.textContent = 'Generate Secure Link';
    }
  }

  // 7. Success Panel Display & Local QR Code Drawing
  function displaySuccessHandover(data) {
    // Populate Links
    recipientLinkInput.value = data.view_url || '';
    manageLinkInput.value = data.manage_url || '';

    // Status Badge & Details
    const displayStatusVal = document.getElementById('display-status-val');
    const displayExpiresKey = document.getElementById('display-expires-key');
    const displayAvailableKey = document.getElementById('display-available-key');

    if (data.status === 'scheduled') {
      statusBadge.textContent = 'Scheduled';
      statusBadge.className = 'status-badge scheduled';
      if (displayStatusVal) displayStatusVal.textContent = 'Scheduled';
      displayAvailableRow.classList.remove('hidden');
      if (displayAvailableKey) displayAvailableKey.textContent = 'Unlocks at';
      displayAvailableAt.textContent = formatDate(data.available_at);
      if (displayExpiresKey) displayExpiresKey.textContent = 'Expiry';
      displayExpiresAt.textContent = formatDate(data.expires_at);
    } else {
      statusBadge.textContent = 'Active';
      statusBadge.className = 'status-badge active';
      if (displayStatusVal) displayStatusVal.textContent = 'Active';
      displayAvailableRow.classList.add('hidden');
      if (displayExpiresKey) displayExpiresKey.textContent = 'Expires at';
      displayExpiresAt.textContent = formatDate(data.expires_at);
    }

    displayViewsRemaining.textContent = `${data.views_remaining || 1} allowed`;
    displayFingerprint.textContent = data.secret_fingerprint || '--';

    // Render QR Code directly on Canvas in-browser
    if (window.QRCode && window.QRCode.drawToCanvas && data.view_url) {
      try {
        window.QRCode.drawToCanvas(qrCanvas, data.view_url, {
          size: 150,
          margin: 4,
          darkColor: '#07090e',
          lightColor: '#ffffff'
        });
      } catch (err) {
        // Fallback gracefully if canvas drawing fails
      }
    }

    // Switch View
    creationSection.classList.remove('active');
    successSection.classList.remove('hidden');
    successSection.classList.add('active');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function formatDate(isoString) {
    if (!isoString) return '--';
    try {
      const d = new Date(isoString);
      return d.toLocaleString(undefined, {
        dateStyle: 'medium',
        timeStyle: 'medium'
      });
    } catch {
      return isoString;
    }
  }

  // 8. Clipboard Copy Handlers with Temporary Feedback
  setupCopyButton(copyViewBtn, recipientLinkInput, 'Copy Link');
  setupCopyButton(copyManageBtn, manageLinkInput, 'Copy Management Link');

  function setupCopyButton(btnElement, inputElement, defaultLabel) {
    btnElement.addEventListener('click', async () => {
      const textToCopy = inputElement.value;
      if (!textToCopy) return;

      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(textToCopy);
        } else {
          inputElement.select();
          document.execCommand('copy');
        }

        btnElement.classList.add('copied');
        btnElement.innerHTML = `<span class="copy-icon">✓</span> <span class="copy-text">Copied securely</span>`;

        setTimeout(() => {
          btnElement.classList.remove('copied');
          btnElement.innerHTML = `<span class="copy-icon">📋</span> <span class="copy-text">${defaultLabel}</span>`;
        }, 2000);
      } catch (err) {
        // Fallback
        inputElement.select();
      }
    });
  }

  // 9. Reset and Create Another Secure Handover
  createAnotherBtn.addEventListener('click', () => {
    // Reset Form Elements
    secretForm.reset();
    secretCharCount.textContent = '0 / 10,000';
    scheduleFieldsWrapper.classList.add('hidden');
    passphraseInput.type = 'password';

    // Clear all inline errors
    document.querySelectorAll('.form-input, .form-textarea, .form-select').forEach((el) => el.classList.remove('error'));
    document.querySelectorAll('.inline-error').forEach((el) => (el.textContent = ''));
    formGlobalError.classList.add('hidden');

    // Switch View back to Creation Section
    successSection.classList.remove('active');
    successSection.classList.add('hidden');
    creationSection.classList.add('active');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  // =========================================================================
  // 10. Presentation Demo Mode (Step 12)
  // =========================================================================
  const demoSection = document.getElementById('demo-section');
  const launchDemoBtn = document.getElementById('launch-demo-btn');
  const launchDemoBtnText = document.getElementById('launch-demo-btn-text');
  const demoSpinner = document.getElementById('demo-spinner');
  const demoDetailsPanel = document.getElementById('demo-details-panel');

  const demoAccessCode = document.getElementById('demo-access-code');
  const demoPassphrase = document.getElementById('demo-passphrase');
  const demoRecipientLink = document.getElementById('demo-recipient-link');
  const copyDemoViewBtn = document.getElementById('copy-demo-view-btn');
  const demoManageLink = document.getElementById('demo-manage-link');
  const copyDemoManageBtn = document.getElementById('copy-demo-manage-btn');
  const demoOpenRecipientBtn = document.getElementById('demo-open-recipient-btn');
  const demoOpenManageBtn = document.getElementById('demo-open-manage-btn');

  const simulateCrawlerBtn = document.getElementById('simulate-crawler-btn');
  const crawlerSimResult = document.getElementById('crawler-sim-result');
  const concurrencyTestBtn = document.getElementById('concurrency-test-btn');
  const concurrencySimResult = document.getElementById('concurrency-sim-result');

  let activeDemoId = null;
  let timelinePollInterval = null;

  // Initialize Demo Mode check
  initDemoMode();

  async function initDemoMode() {
    if (!demoSection) return;
    try {
      const res = await fetch('/api/demo/status');
      if (res.ok) {
        const data = await res.json();
        if (data && data.demo_enabled) {
          demoSection.classList.remove('hidden');
        }
      }
    } catch {
      // Keep hidden if demo status check fails
    }
  }

  // Setup Demo Copy Buttons
  if (copyDemoViewBtn && demoRecipientLink) {
    setupCopyButton(copyDemoViewBtn, demoRecipientLink, 'Copy');
  }
  if (copyDemoManageBtn && demoManageLink) {
    setupCopyButton(copyDemoManageBtn, demoManageLink, 'Copy');
  }

  // Launch Demo Scenario
  if (launchDemoBtn) {
    launchDemoBtn.addEventListener('click', async () => {
      try {
        launchDemoBtn.disabled = true;
        if (launchDemoBtnText) launchDemoBtnText.textContent = 'Launching Demo...';
        if (demoSpinner) demoSpinner.classList.remove('hidden');

        const res = await fetch('/api/demo/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({})
        });

        if (!res.ok) {
          throw new Error('Failed to launch demo scenario.');
        }

        const data = await res.json();
        activeDemoId = data.id;

        if (demoAccessCode) demoAccessCode.textContent = data.access_code;
        if (demoPassphrase) demoPassphrase.textContent = data.passphrase;
        if (demoRecipientLink) demoRecipientLink.value = data.view_url;
        if (demoManageLink) demoManageLink.value = data.manage_url;
        if (demoOpenRecipientBtn) demoOpenRecipientBtn.href = data.view_url;
        if (demoOpenManageBtn) demoOpenManageBtn.href = data.manage_url;

        // Reset simulation result displays
        if (crawlerSimResult) {
          crawlerSimResult.textContent = '';
          crawlerSimResult.className = 'sim-result-box hidden';
        }
        if (concurrencySimResult) {
          concurrencySimResult.textContent = '';
          concurrencySimResult.className = 'sim-result-box hidden';
        }

        if (demoDetailsPanel) demoDetailsPanel.classList.remove('hidden');

        // Fetch initial timeline and begin 3-second polling
        await pollTimeline();
        startTimelinePolling();
      } catch (err) {
        alert(err.message || 'Error launching demo scenario.');
      } finally {
        launchDemoBtn.disabled = false;
        if (launchDemoBtnText) launchDemoBtnText.textContent = 'Launch Demo Scenario';
        if (demoSpinner) demoSpinner.classList.add('hidden');
      }
    });
  }

  function startTimelinePolling() {
    stopTimelinePolling();
    timelinePollInterval = setInterval(pollTimeline, 3000);
  }

  function stopTimelinePolling() {
    if (timelinePollInterval) {
      clearInterval(timelinePollInterval);
      timelinePollInterval = null;
    }
  }

  window.addEventListener('beforeunload', stopTimelinePolling);
  window.addEventListener('pagehide', stopTimelinePolling);

  async function pollTimeline() {
    if (!activeDemoId) return;
    try {
      const res = await fetch(`/api/demo/${activeDemoId}/timeline`);
      if (!res.ok) return;
      const data = await res.json();
      if (!data || !Array.isArray(data.journey)) return;

      data.journey.forEach((step) => {
        const stepEl = document.getElementById(`step-${step.step}`);
        if (!stepEl) return;
        const badge = stepEl.querySelector('.step-status-badge');

        if (step.completed) {
          stepEl.classList.add('completed');
          if (badge) {
            badge.textContent = 'Completed';
            badge.classList.remove('pending');
            badge.classList.add('completed');
          }
        } else {
          stepEl.classList.remove('completed');
          if (badge) {
            badge.textContent = 'Pending';
            badge.classList.remove('completed');
            badge.classList.add('pending');
          }
        }
      });
    } catch {
      // Ignore background poll errors
    }
  }

  // Simulate Crawler Visit
  if (simulateCrawlerBtn) {
    simulateCrawlerBtn.addEventListener('click', async () => {
      if (!activeDemoId) return;
      try {
        simulateCrawlerBtn.disabled = true;
        simulateCrawlerBtn.textContent = 'Simulating...';
        crawlerSimResult.className = 'sim-result-box hidden';

        const res = await fetch(`/api/demo/${activeDemoId}/simulate-crawler`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({})
        });

        const data = await res.json();
        if (res.ok) {
          crawlerSimResult.textContent = data.message || 'Bot blocked - secret remains protected.';
          crawlerSimResult.className = 'sim-result-box success';
          await pollTimeline();
        } else {
          crawlerSimResult.textContent = data.error || 'Failed to simulate crawler.';
          crawlerSimResult.className = 'sim-result-box error';
        }
      } catch {
        crawlerSimResult.textContent = 'Network error during simulation.';
        crawlerSimResult.className = 'sim-result-box error';
      } finally {
        simulateCrawlerBtn.disabled = false;
        simulateCrawlerBtn.innerHTML = '<span>🤖</span> Simulate Crawler Visit';
      }
    });
  }

  // Run Concurrency Test
  if (concurrencyTestBtn) {
    concurrencyTestBtn.addEventListener('click', async () => {
      if (!activeDemoId) return;
      try {
        concurrencyTestBtn.disabled = true;
        concurrencyTestBtn.textContent = 'Running 20 parallel reveals...';
        concurrencySimResult.className = 'sim-result-box hidden';

        const res = await fetch(`/api/demo/${activeDemoId}/concurrency-test`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({})
        });

        const data = await res.json();
        if (res.ok) {
          concurrencySimResult.textContent = data.message || '20 parallel requests: 1 revealed, 19 blocked.';
          concurrencySimResult.className = 'sim-result-box success';
          await pollTimeline();
        } else {
          concurrencySimResult.textContent = data.error || 'Concurrency test failed.';
          concurrencySimResult.className = 'sim-result-box error';
        }
      } catch {
        concurrencySimResult.textContent = 'Network error during concurrency test.';
        concurrencySimResult.className = 'sim-result-box error';
      } finally {
        concurrencyTestBtn.disabled = false;
        concurrencyTestBtn.innerHTML = '<span>⚡</span> Run Concurrency Test';
      }
    });
  }
});
