// VaultLink Recipient View Client Script
document.addEventListener('DOMContentLoaded', () => {
  const metaElem = document.getElementById('handover-meta');
  if (!metaElem) return;

  const secretId = metaElem.getAttribute('data-id');
  const status = metaElem.getAttribute('data-status');
  const availableAtStr = metaElem.getAttribute('data-available-at');
  const expiresAtStr = metaElem.getAttribute('data-expires-at');

  const availableAt = availableAtStr ? new Date(availableAtStr).getTime() : 0;
  const expiresAt = expiresAtStr ? new Date(expiresAtStr).getTime() : 0;

  const countdownDisplay = document.getElementById('countdown-display');
  const recipientForm = document.getElementById('recipient-form');
  const accessCodeInput = document.getElementById('access-code-input');
  const passphraseInput = document.getElementById('passphrase-input');
  const togglePassBtn = document.getElementById('toggle-passphrase-btn');
  const verifyBtn = document.getElementById('verify-btn');
  const verifyBtnText = document.getElementById('verify-btn-text');
  const verifySpinner = document.getElementById('verify-spinner');
  const errorBanner = document.getElementById('verify-error-banner');
  const errorText = document.getElementById('verify-error-text');
  const verifiedSection = document.getElementById('verified-section');
  const revealBtn = document.getElementById('reveal-btn');
  const revealNoticeBanner = document.getElementById('reveal-notice-banner');

  // In-memory verification token storage (strictly never stored in localStorage, sessionStorage, or cookies)
  let activeVerificationToken = null;

  // Once server reports active status, enable inputs
  if (status === 'active') {
    if (accessCodeInput) accessCodeInput.disabled = false;
    if (passphraseInput) passphraseInput.disabled = false;
    if (verifyBtn) verifyBtn.disabled = false;
  }

  // Format date helper (UTC)
  function formatDate(isoStr) {
    if (!isoStr) return '--';
    try {
      const d = new Date(isoStr);
      return d.toUTCString().replace('GMT', 'UTC');
    } catch (e) {
      return isoStr;
    }
  }

  // Update formatted timestamps in the DOM
  const expElem = document.getElementById('expiry-formatted');
  if (expElem && expiresAtStr) {
    expElem.textContent = formatDate(expiresAtStr);
  }
  const availElem = document.getElementById('available-formatted');
  if (availElem && availableAtStr) {
    availElem.textContent = formatDate(availableAtStr);
  }

  // Format duration into readable timer
  function formatDuration(ms) {
    if (ms <= 0) return '00:00:00';
    const totalSeconds = Math.floor(ms / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;

    const pad = (n) => String(n).padStart(2, '0');
    if (hours > 0) {
      return `${pad(hours)}h ${pad(minutes)}m ${pad(seconds)}s`;
    }
    return `${pad(minutes)}m ${pad(seconds)}s`;
  }

  let timerInterval = null;
  let reloaded = false;

  function updateTimer() {
    const now = Date.now();

    if (status === 'scheduled') {
      const remaining = availableAt - now;
      if (remaining <= 0) {
        if (countdownDisplay) countdownDisplay.textContent = 'Unlocked';
        clearInterval(timerInterval);
        if (!reloaded) {
          reloaded = true;
          window.location.reload();
        }
        return;
      }
      if (countdownDisplay) {
        countdownDisplay.textContent = formatDuration(remaining);
      }
    } else if (status === 'active') {
      const remaining = expiresAt - now;
      if (remaining <= 0) {
        if (countdownDisplay) countdownDisplay.textContent = 'Expired';
        clearInterval(timerInterval);
        window.location.reload();
        return;
      }
      if (countdownDisplay) {
        countdownDisplay.textContent = formatDuration(remaining);
      }
    }
  }

  updateTimer();
  timerInterval = setInterval(updateTimer, 1000);

  // Passphrase visibility toggle
  if (togglePassBtn && passphraseInput) {
    togglePassBtn.addEventListener('click', () => {
      const isPassword = passphraseInput.type === 'password';
      passphraseInput.type = isPassword ? 'text' : 'password';
    });
  }

  // Only allow numeric input in access code field
  if (accessCodeInput) {
    accessCodeInput.addEventListener('input', (e) => {
      e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6);
    });
  }

  function hideError() {
    if (errorBanner) {
      errorBanner.classList.add('hidden');
    }
  }

  function showError(msg) {
    if (errorBanner && errorText) {
      errorText.textContent = msg;
      errorBanner.classList.remove('hidden');
      errorBanner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  function setLoading(loading) {
    if (verifyBtn) {
      verifyBtn.disabled = loading;
    }
    if (verifySpinner) {
      if (loading) verifySpinner.classList.remove('hidden');
      else verifySpinner.classList.add('hidden');
    }
    if (verifyBtnText) {
      verifyBtnText.textContent = loading ? 'Verifying...' : 'Verify Secure Handover';
    }
  }

  // Handle Verification Form Submission
  if (recipientForm) {
    recipientForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      hideError();

      const accessCode = (accessCodeInput?.value || '').trim();
      const passphrase = (passphraseInput?.value || '');

      if (!/^\d{6}$/.test(accessCode)) {
        showError('Verification failed. Please check your secure handover details.');
        return;
      }

      if (!passphrase || passphrase.length < 1) {
        showError('Verification failed. Please check your secure handover details.');
        return;
      }

      setLoading(true);

      try {
        const response = await fetch(`/api/secrets/${encodeURIComponent(secretId)}/verify`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            access_code: accessCode,
            passphrase: passphrase
          })
        });

        const data = await response.json().catch(() => ({}));

        // Zero-knowledge credential memory wipe
        if (accessCodeInput) accessCodeInput.value = '';
        if (passphraseInput) passphraseInput.value = '';

        if (response.status === 200 && data.verified && data.verification_token) {
          // Store token strictly in JavaScript variable closure in memory
          activeVerificationToken = data.verification_token;

          // Transition UI to verified state
          recipientForm.classList.add('hidden');
          if (verifiedSection) {
            verifiedSection.classList.remove('hidden');
          }
        } else if (response.status === 429) {
          showError('Too many attempts. Please wait before trying again.');
        } else {
          showError('Verification failed. Please check your secure handover details.');
        }
      } catch (err) {
        showError('Verification failed. Please check your secure handover details.');
      } finally {
        setLoading(false);
      }
    });
  }

  // Step 8 Reveal Button: Atomic Decryption & Self-Destruction
  const revealSpinner = document.getElementById('reveal-spinner');
  const revealBtnText = document.getElementById('reveal-btn-text');
  const revealPanel = document.getElementById('reveal-panel');
  const revealedSecretText = document.getElementById('revealed-secret-text');
  const copySecretBtn = document.getElementById('copy-secret-btn');
  const copySecretBtnText = document.getElementById('copy-secret-btn-text');
  const revealCountdownNum = document.getElementById('reveal-countdown-num');
  const revealProgressBar = document.getElementById('reveal-progress-bar');
  const destroyedPanel = document.getElementById('destroyed-panel');

  if (revealBtn) {
    revealBtn.addEventListener('click', async () => {
      if (!activeVerificationToken) {
        showError('Secret unavailable, expired, or already destroyed.');
        return;
      }

      // Disable button immediately
      revealBtn.disabled = true;
      if (revealSpinner) revealSpinner.classList.remove('hidden');
      if (revealBtnText) revealBtnText.textContent = 'Decrypting...';
      hideError();

      try {
        const response = await fetch(`/api/secrets/${encodeURIComponent(secretId)}/reveal`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            verification_token: activeVerificationToken
          })
        });

        // Immediately clear verification token from JavaScript memory
        activeVerificationToken = null;

        const data = await response.json().catch(() => ({}));

        if (response.status === 200 && data.secret) {
          // Hide verification state and countdown card
          if (verifiedSection) verifiedSection.classList.add('hidden');
          const mainCardHeader = document.querySelector('.main-card .card-header');
          if (mainCardHeader) mainCardHeader.style.display = 'none';
          const countdownCard = document.querySelector('.countdown-card');
          if (countdownCard) countdownCard.style.display = 'none';
          const detailsBox = document.querySelector('.details-box');
          if (detailsBox) detailsBox.style.display = 'none';
          const advisoryCard = document.querySelector('.security-advisory-card');
          if (advisoryCard) advisoryCard.style.display = 'none';

          // Show protected reveal panel
          if (revealPanel) revealPanel.classList.remove('hidden');
          if (revealedSecretText) revealedSecretText.value = data.secret;

          // Ephemeral in-memory acknowledgement token (Step 11)
          let activeAcknowledgementToken = data.acknowledgement_token || null;
          let ackTimer = null;

          // 15-Minute Acknowledgement Expiry Timer
          const ackExpirySeconds = data.acknowledgement_expires_in_seconds || 900;
          const ackExpiresAtTime = Date.now() + ackExpirySeconds * 1000;
          const ackCountdownBadge = document.getElementById('ack-countdown-badge');
          const ackCheckbox = document.getElementById('ack-checkbox');
          const acknowledgeBtn = document.getElementById('acknowledge-btn');
          const ackSpinner = document.getElementById('ack-spinner');
          const ackBtnText = document.getElementById('ack-btn-text');
          const ackSuccessBox = document.getElementById('ack-success-box');
          const ackExpiredBox = document.getElementById('ack-expired-box');
          const ackControls = document.getElementById('ack-controls');

          if (ackCountdownBadge) {
            ackTimer = setInterval(() => {
              const secondsLeft = Math.max(0, Math.floor((ackExpiresAtTime - Date.now()) / 1000));
              if (secondsLeft > 0) {
                const mins = Math.floor(secondsLeft / 60);
                const secs = secondsLeft % 60;
                ackCountdownBadge.textContent = `${mins}m ${secs < 10 ? '0' : ''}${secs}s`;
              } else {
                clearInterval(ackTimer);
                activeAcknowledgementToken = null;
                if (ackControls) ackControls.classList.add('hidden');
                if (ackExpiredBox) {
                  ackExpiredBox.textContent = 'Acknowledgement window has expired.';
                  ackExpiredBox.classList.remove('hidden');
                }
                ackCountdownBadge.textContent = 'Expired';
              }
            }, 1000);
          }

          // Handle Acknowledgement Form Interactions
          if (ackCheckbox && acknowledgeBtn) {
            ackCheckbox.addEventListener('change', () => {
              acknowledgeBtn.disabled = !ackCheckbox.checked;
              acknowledgeBtn.style.opacity = ackCheckbox.checked ? '1' : '0.5';
            });

            acknowledgeBtn.addEventListener('click', async () => {
              if (!ackCheckbox.checked || !activeAcknowledgementToken) return;

              acknowledgeBtn.disabled = true;
              ackCheckbox.disabled = true;
              if (ackSpinner) ackSpinner.classList.remove('hidden');
              if (ackBtnText) ackBtnText.textContent = 'Acknowledging...';

              try {
                const ackResponse = await fetch(`/api/secrets/${encodeURIComponent(secretId)}/acknowledge`, {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json'
                  },
                  body: JSON.stringify({
                    acknowledgement_token: activeAcknowledgementToken
                  })
                });

                // Clear acknowledgement token from JavaScript memory immediately
                activeAcknowledgementToken = null;
                if (ackTimer) clearInterval(ackTimer);

                const ackData = await ackResponse.json().catch(() => ({}));

                if (ackResponse.status === 200 && ackData.acknowledged) {
                  if (ackControls) ackControls.classList.add('hidden');
                  if (ackSuccessBox) ackSuccessBox.classList.remove('hidden');
                  if (ackCountdownBadge) ackCountdownBadge.textContent = 'Acknowledged';
                } else {
                  if (ackControls) ackControls.classList.add('hidden');
                  if (ackExpiredBox) {
                    ackExpiredBox.textContent = 'Acknowledgement window has expired.';
                    ackExpiredBox.classList.remove('hidden');
                  }
                }
              } catch (err) {
                activeAcknowledgementToken = null;
                if (ackTimer) clearInterval(ackTimer);
                if (ackControls) ackControls.classList.add('hidden');
                if (ackExpiredBox) {
                  ackExpiredBox.textContent = 'Acknowledgement window has expired.';
                  ackExpiredBox.classList.remove('hidden');
                }
              }
            });
          }

          // 15-Second Self-Destruction Countdown for the secret plaintext
          const totalSeconds = data.display_seconds || 15;
          let remainingSeconds = totalSeconds;

          const revealInterval = setInterval(() => {
            remainingSeconds -= 1;
            if (revealCountdownNum) {
              revealCountdownNum.textContent = String(Math.max(0, remainingSeconds));
            }
            if (revealProgressBar) {
              const progressPct = (remainingSeconds / totalSeconds) * 100;
              revealProgressBar.style.width = `${Math.max(0, progressPct)}%`;
            }

            if (remainingSeconds <= 0) {
              clearInterval(revealInterval);

              // Permanently wipe secret plaintext from memory and DOM
              if (revealedSecretText) {
                revealedSecretText.value = '';
                revealedSecretText.remove();
              }
              const secretActiveBox = document.getElementById('secret-active-box');
              if (secretActiveBox) {
                secretActiveBox.remove();
              }
              const secretErasedBox = document.getElementById('secret-erased-box');
              if (secretErasedBox) {
                secretErasedBox.classList.remove('hidden');
              }

              // Prevent back navigation recovery
              if (window.history && window.history.replaceState) {
                window.history.replaceState(null, '', window.location.href);
              }
            }
          }, 1000);

          // Copy Secret Action
          if (copySecretBtn) {
            copySecretBtn.addEventListener('click', async () => {
              try {
                if (data.secret) {
                  await navigator.clipboard.writeText(data.secret);
                  if (copySecretBtnText) {
                    const orig = copySecretBtnText.textContent;
                    copySecretBtnText.textContent = '✓ Copied securely';
                    copySecretBtn.classList.add('copied');
                    setTimeout(() => {
                      copySecretBtnText.textContent = orig;
                      copySecretBtn.classList.remove('copied');
                    }, 2000);
                  }
                }
              } catch (err) {
                // Clipboard fallback
                if (revealedSecretText) {
                  revealedSecretText.select();
                  document.execCommand('copy');
                }
              }
            });
          }
        } else {
          showError('Secret unavailable, expired, or already destroyed.');
          revealBtn.disabled = false;
          if (revealSpinner) revealSpinner.classList.add('hidden');
          if (revealBtnText) revealBtnText.textContent = 'Reveal & Destroy Secret';
        }
      } catch (err) {
        showError('Secret unavailable, expired, or already destroyed.');
        revealBtn.disabled = false;
        if (revealSpinner) revealSpinner.classList.add('hidden');
        if (revealBtnText) revealBtnText.textContent = 'Reveal & Destroy Secret';
      }
    });
  }
});


