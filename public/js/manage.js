// VaultLink Sender Management Dashboard Client Script
document.addEventListener('DOMContentLoaded', () => {
  const metaElem = document.getElementById('dashboard-meta');
  if (!metaElem) return;

  const secretId = metaElem.getAttribute('data-id');
  const csrfTokenInput = document.getElementById('csrf-token');
  const csrfToken = csrfTokenInput ? csrfTokenInput.value : '';

  const panicBurnBtn = document.getElementById('panic-burn-btn');
  const burnModal = document.getElementById('burn-modal');
  const cancelBtn = document.getElementById('modal-cancel-btn');
  const confirmBurnBtn = document.getElementById('modal-confirm-burn-btn');
  const modalSpinner = document.getElementById('modal-spinner');
  const modalConfirmText = document.getElementById('modal-confirm-text');

  const statusBadge = document.getElementById('dashboard-status-badge');
  const statusMessage = document.getElementById('dashboard-status-message');
  const panicBurnContainer = document.getElementById('panic-burn-container');
  const revokedAtRow = document.getElementById('revoked-at-row');
  const dashboardRevokedAt = document.getElementById('dashboard-revoked-at');
  const timelineList = document.getElementById('timeline-list');
  const successBanner = document.getElementById('dashboard-success-banner');
  const errorBanner = document.getElementById('dashboard-error-banner');

  function showModal() {
    if (burnModal) burnModal.classList.remove('hidden');
  }

  function hideModal() {
    if (burnModal) burnModal.classList.add('hidden');
  }

  function setBurningState(burning) {
    if (confirmBurnBtn) confirmBurnBtn.disabled = burning;
    if (cancelBtn) cancelBtn.disabled = burning;
    if (modalSpinner) {
      if (burning) modalSpinner.classList.remove('hidden');
      else modalSpinner.classList.add('hidden');
    }
    if (modalConfirmText) {
      modalConfirmText.textContent = burning ? 'Revoking...' : 'Burn Secret Permanently';
    }
  }

  if (panicBurnBtn) {
    panicBurnBtn.addEventListener('click', showModal);
  }

  if (cancelBtn) {
    cancelBtn.addEventListener('click', hideModal);
  }

  if (burnModal) {
    burnModal.addEventListener('click', (e) => {
      if (e.target === burnModal) {
        hideModal();
      }
    });
  }

  if (confirmBurnBtn) {
    confirmBurnBtn.addEventListener('click', async () => {
      setBurningState(true);
      if (errorBanner) errorBanner.classList.add('hidden');
      if (successBanner) successBanner.classList.add('hidden');

      try {
        const response = await fetch(`/api/secrets/${encodeURIComponent(secretId)}/panic-burn`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
          },
          body: JSON.stringify({
            csrf_token: csrfToken
          })
        });

        const data = await response.json().catch(() => ({}));

        if (response.ok && data.success && data.status === 'revoked') {
          hideModal();

          // 1. Update status badge
          if (statusBadge) {
            statusBadge.textContent = 'Revoked';
            statusBadge.className = 'status-badge revoked';
          }

          // 2. Update status message
          if (statusMessage) {
            statusMessage.textContent = 'The sender permanently revoked this handover.';
          }

          // 3. Remove Panic Burn button
          if (panicBurnContainer) {
            panicBurnContainer.classList.add('hidden');
          }

          // 4. Update Revoked at row
          const nowUtc = new Date().toUTCString().replace('GMT', 'UTC');
          if (dashboardRevokedAt) {
            dashboardRevokedAt.textContent = nowUtc;
          }
          if (revokedAtRow) {
            revokedAtRow.classList.remove('hidden');
          }

          // 5. Append event to timeline
          if (timelineList) {
            const emptyNotice = timelineList.querySelector('.timeline-empty');
            if (emptyNotice) emptyNotice.remove();

            const newEvent = document.createElement('div');
            newEvent.className = 'timeline-item';
            newEvent.innerHTML = `
              <div class="timeline-dot" style="background: #ef4444; border-color: rgba(239, 68, 68, 0.4);"></div>
              <div class="timeline-content">
                <span class="timeline-title" style="color: #f87171;">Revoked</span>
                <span class="timeline-time mono">${nowUtc}</span>
              </div>
            `;
            timelineList.appendChild(newEvent);
          }

          // 6. Show success notice
          if (successBanner) {
            successBanner.classList.remove('hidden');
            successBanner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }
        } else {
          hideModal();
          if (errorBanner) {
            errorBanner.classList.remove('hidden');
            errorBanner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }
        }
      } catch (err) {
        hideModal();
        if (errorBanner) {
          errorBanner.classList.remove('hidden');
          errorBanner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      } finally {
        setBurningState(false);
      }
    });
  }
});
