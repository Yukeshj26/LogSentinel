/**
 * LogSentinel — Real-Time Log Analysis Dashboard
 * Vanilla JS, no external dependencies.
 */

// ── State ────────────────────────────────────────
const state = {
  entries: [],          // all received log entries
  threats: [],          // all received threats
  sse: null,
  streaming: true,
  sortCol: 'timestamp',
  sortDir: 'desc',
  filterAction: '',
  filterStatus: '',
  filterIp: '',
  sevFilter: 'ALL',
  totalEvents: 0,
  totalThreats: 0,
  totalFailures: 0,
  bufferSize: 0,
  isAdmin: false,
  isElevating: false,
};

// ── DOM refs ─────────────────────────────────────
const dom = {
  liveIndicator:   document.getElementById('liveIndicator'),
  pulseDot:        document.getElementById('pulseDot'),
  liveLabel:       document.getElementById('liveLabel'),
  adminBadge:      document.getElementById('adminBadge'),
  demoBanner:      document.getElementById('demoBanner'),
  demoBannerText:  document.getElementById('demoBannerText'),
  elevateControls: document.getElementById('elevateControls'),
  elevateBtn:      document.getElementById('elevateBtn'),
  elevateBanner:   document.getElementById('elevateBanner'),
  elevateSpinner:  document.getElementById('elevateSpinner'),
  elevateBannerText: document.getElementById('elevateBannerText'),
  elevateReconnectHint: document.getElementById('elevateReconnectHint'),

  toggleBtn:       document.getElementById('toggleStreamBtn'),
  toggleText:      document.getElementById('toggleStreamText'),
  clearBtn:        document.getElementById('clearBtn'),
  exportCsvBtn:    document.getElementById('exportCsvBtn'),
  exportReportBtn: document.getElementById('exportReportBtn'),

  statEventsVal:   document.getElementById('statEventsVal'),
  statThreatsVal:  document.getElementById('statThreatsVal'),
  statFailuresVal: document.getElementById('statFailuresVal'),
  statBufferVal:   document.getElementById('statBufferVal'),

  velocityChart:     document.getElementById('velocityChart'),
  velocityRateBadge: document.getElementById('velocityRateBadge'),

  threatsGrid:     document.getElementById('threatsGrid'),
  threatsEmpty:    document.getElementById('threatsEmpty'),
  threatCount:     document.getElementById('threatCount'),

  logTable:        document.getElementById('logTable'),
  logTableBody:    document.getElementById('logTableBody'),
  logEmpty:        document.getElementById('logEmpty'),
  logCount:        document.getElementById('logCount'),

  filterAction:    document.getElementById('filterAction'),
  filterStatus:    document.getElementById('filterStatus'),
  filterIp:        document.getElementById('filterIp'),

  filePanelToggle: document.getElementById('filePanelToggle'),
  filePanelBody:   document.getElementById('filePanelBody'),
  collapseArrow:   document.getElementById('collapseArrow'),

  dropZone:        document.getElementById('dropZone'),
  fileInput:       document.getElementById('fileInput'),
  browseLink:      document.getElementById('browseLink'),
  pasteInput:      document.getElementById('pasteInput'),
  analyzePasteBtn: document.getElementById('analyzePasteBtn'),

  analysisResults: document.getElementById('analysisResults'),
  analysisMeta:    document.getElementById('analysisMeta'),
  analysisContent: document.getElementById('analysisContent'),
  fileLoading:     document.getElementById('fileLoading'),

  footerStatus:    document.getElementById('footerStatus'),

  threatDetailModal:        document.getElementById('threatDetailModal'),
  threatModalTitle:         document.getElementById('threatModalTitle'),
  threatModalSeverityBadge: document.getElementById('threatModalSeverityBadge'),
  threatModalSubtitle:      document.getElementById('threatModalSubtitle'),
  threatModalIcon:          document.getElementById('threatModalIcon'),
  threatModalBody:          document.getElementById('threatModalBody'),
  threatModalCloseBtn:      document.getElementById('threatModalCloseBtn'),
  threatModalDismissBtn:    document.getElementById('threatModalDismissBtn'),

  dossierDrawer:     document.getElementById('dossierDrawer'),
  dossierBackdrop:   document.getElementById('dossierBackdrop'),
  dossierCloseBtn:   document.getElementById('dossierCloseBtn'),
  dossierBadge:      document.getElementById('dossierBadge'),
  dossierTitle:      document.getElementById('dossierTitle'),
  dossierBody:       document.getElementById('dossierBody'),

  reportModal:           document.getElementById('reportModal'),
  reportModalContent:     document.getElementById('reportModalContent'),
  reportModalCloseBtn:   document.getElementById('reportModalCloseBtn'),
  reportModalDismissBtn: document.getElementById('reportModalDismissBtn'),
  reportPrintBtn:        document.getElementById('reportPrintBtn'),
};

// ── Real-Time Velocity Timeline ───────────────────
const velocityHistory = [];
const VELOCITY_POINTS = 50;
let currentBucket = { events: 0, failures: 0, threats: 0 };

for (let i = 0; i < VELOCITY_POINTS; i++) {
  velocityHistory.push({ events: 0, failures: 0, threats: 0 });
}

function trackVelocityEvent(statusCode) {
  currentBucket.events++;
  const sc = String(statusCode || '').toUpperCase();
  if (sc.includes('FAIL') || sc.includes('DENIED') || sc.includes('UNAUTH') || sc === '401' || sc === '403') {
    currentBucket.failures++;
  }
}

function trackVelocityThreat() {
  currentBucket.threats++;
}

function tickVelocity() {
  velocityHistory.push({ ...currentBucket });
  if (velocityHistory.length > VELOCITY_POINTS) {
    velocityHistory.shift();
  }
  const eps = currentBucket.events;
  if (dom.velocityRateBadge) {
    dom.velocityRateBadge.textContent = `${eps} eps`;
  }
  currentBucket = { events: 0, failures: 0, threats: 0 };
  drawVelocityChart();
}

function drawVelocityChart() {
  const canvas = dom.velocityChart;
  if (!canvas) return;
  const parent = canvas.parentElement;
  if (!parent) return;

  const width = parent.clientWidth || 600;
  const height = 95;
  const dpr = window.devicePixelRatio || 1;

  if (canvas.width !== width * dpr || canvas.height !== height * dpr) {
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = width + 'px';
    canvas.style.height = height + 'px';
  }

  const ctx = canvas.getContext('2d');
  ctx.save();
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, width, height);

  let maxVal = 5;
  for (const pt of velocityHistory) {
    if (pt.events > maxVal) maxVal = pt.events;
    if (pt.failures > maxVal) maxVal = pt.failures;
    if (pt.threats > maxVal) maxVal = pt.threats;
  }
  maxVal = Math.ceil(maxVal * 1.25);

  const paddingLeft = 8;
  const paddingRight = 8;
  const paddingTop = 12;
  const paddingBottom = 16;
  const chartW = width - paddingLeft - paddingRight;
  const chartH = height - paddingTop - paddingBottom;
  const stepX = chartW / (VELOCITY_POINTS - 1);

  // Background grid
  ctx.strokeStyle = '#F1F5F9';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 3; i++) {
    const y = paddingTop + (chartH / 3) * i;
    ctx.beginPath();
    ctx.moveTo(paddingLeft, y);
    ctx.lineTo(width - paddingRight, y);
    ctx.stroke();
  }

  function drawSeries(key, strokeColor, fillColor, lineWidth) {
    ctx.beginPath();
    for (let i = 0; i < velocityHistory.length; i++) {
      const val = velocityHistory[i][key];
      const x = paddingLeft + i * stepX;
      const y = paddingTop + chartH - (val / maxVal) * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    if (fillColor) {
      ctx.save();
      const lastX = paddingLeft + (velocityHistory.length - 1) * stepX;
      const firstX = paddingLeft;
      const baselineY = paddingTop + chartH;
      ctx.lineTo(lastX, baselineY);
      ctx.lineTo(firstX, baselineY);
      ctx.closePath();
      ctx.fillStyle = fillColor;
      ctx.fill();
      ctx.restore();
    }
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = lineWidth;
    ctx.stroke();
  }

  // 1. Total events (blue with gradient)
  const grad = ctx.createLinearGradient(0, paddingTop, 0, paddingTop + chartH);
  grad.addColorStop(0, 'rgba(37, 99, 235, 0.2)');
  grad.addColorStop(1, 'rgba(37, 99, 235, 0.01)');
  drawSeries('events', '#2563EB', grad, 2);

  // 2. Failures (orange)
  drawSeries('failures', '#EA580C', null, 1.8);

  // 3. Threats (red dots)
  for (let i = 0; i < velocityHistory.length; i++) {
    const threatVal = velocityHistory[i].threats;
    if (threatVal > 0) {
      const x = paddingLeft + i * stepX;
      const y = paddingTop + chartH - (threatVal / maxVal) * chartH;
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#DC2626';
      ctx.fill();
      ctx.strokeStyle = '#FFFFFF';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }
  }

  // Baseline
  ctx.strokeStyle = '#E2E8F0';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(paddingLeft, paddingTop + chartH);
  ctx.lineTo(width - paddingRight, paddingTop + chartH);
  ctx.stroke();

  ctx.restore();
}

function initVelocityChart() {
  setInterval(tickVelocity, 1000);
  window.addEventListener('resize', drawVelocityChart);
  drawVelocityChart();
}

// ── SSE Stream ───────────────────────────────────
function connectSSE() {
  if (dom.sse) {
    try { dom.sse.close(); } catch (e) {}
  }
  setStatus('connecting');
  const es = new EventSource('/api/stream');
  dom.sse = es;

  es.onopen = () => setStatus('connected');

  es.addEventListener('log-entry', e => {
    if (!state.streaming) return;
    try {
      const entry = JSON.parse(e.data);
      state.entries.unshift(entry);
      if (state.entries.length > 500) state.entries.pop();
      trackVelocityEvent(entry.statusCode);
      renderTableRow(entry, true);
      updateLogCount();
    } catch (err) { console.error('Error parsing log-entry:', err); }
  });

  es.addEventListener('threat', e => {
    if (!state.streaming) return;
    try {
      const threat = JSON.parse(e.data);
      state.threats.unshift(threat);
      trackVelocityThreat();
      renderThreatCard(threat);
      updateThreatCount();
      flashThreatPanel();
    } catch (err) { console.error('Error parsing threat:', err); }
  });

  es.addEventListener('stats', e => {
    try {
      const stats = JSON.parse(e.data);
      updateStats(stats);
    } catch (err) { console.error('Error parsing stats:', err); }
  });

  es.addEventListener('status', e => {
    try {
      const stats = JSON.parse(e.data);
      updateStats(stats);
    } catch (err) { console.error('Error parsing status:', err); }
  });

  es.addEventListener('heartbeat', e => {
    try {
      const hb = JSON.parse(e.data);
      if (hb.demo !== undefined && !state.isAdmin) {
        dom.demoBanner.style.display = hb.demo ? 'flex' : 'none';
      }
      updateFooterTime();
    } catch (err) {}
  });

  es.onerror = () => {
    setStatus('error');
    try { es.close(); } catch (e) {}
    // Auto-reconnect after 4s unless elevating
    if (!state.isElevating) {
      setTimeout(() => { if (state.streaming) connectSSE(); }, 4000);
    }
  };
}

function setStatus(s) {
  dom.liveIndicator.className = 'live-indicator ' + (s === 'connected' ? 'connected' : s === 'error' ? 'error' : '');
  dom.liveLabel.textContent = s === 'connected' ? 'LIVE' : s === 'error' ? 'Reconnecting...' : 'Connecting...';
  dom.footerStatus.textContent = s === 'connected'
    ? (state.isAdmin ? 'Streaming live Windows Security event logs (Admin)' : 'Connected — streaming events (Demo mode)')
    : s === 'error' ? 'Connection lost — retrying...' : 'Connecting to event stream...';
}

// ── Stats ────────────────────────────────────────
function updateStats(stats) {
  animateCounter(dom.statEventsVal,   stats.totalEvents   ?? state.totalEvents);
  animateCounter(dom.statThreatsVal,  stats.totalThreats  ?? state.totalThreats);
  animateCounter(dom.statFailuresVal, stats.totalFailures ?? state.totalFailures);
  animateCounter(dom.statBufferVal,   stats.bufferSize    ?? state.bufferSize);

  state.totalEvents   = stats.totalEvents   ?? state.totalEvents;
  state.totalThreats  = stats.totalThreats  ?? state.totalThreats;
  state.totalFailures = stats.totalFailures ?? state.totalFailures;
  state.bufferSize    = stats.bufferSize    ?? state.bufferSize;

  if (stats.isAdmin !== undefined) {
    state.isAdmin = stats.isAdmin;
    if (state.isAdmin) {
      dom.adminBadge.style.display = 'inline-flex'; const m = document.getElementById('elevateModal'); if (m) m.style.display = 'none';
      dom.demoBanner.style.display = 'none';
    } else {
      dom.adminBadge.style.display = 'none';
      if (stats.demoMode !== undefined) {
        dom.demoBanner.style.display = stats.demoMode ? 'flex' : 'none';
      }
    }
  } else if (stats.demoMode !== undefined && !state.isAdmin) {
    dom.demoBanner.style.display = stats.demoMode ? 'flex' : 'none';
  }

  if (stats.canElevate !== undefined && dom.elevateControls) {
    dom.elevateControls.style.display = stats.canElevate ? 'block' : 'none';
  }
}

function animateCounter(el, newVal) {
  if (el.textContent === String(newVal)) return;
  el.textContent = newVal;
  el.classList.remove('updated');
  void el.offsetWidth;
  el.classList.add('updated');
}

// ── In-App Admin Elevation ───────────────────────
function setupElevation() {
  const modal = document.getElementById('elevateModal');
  const closeBtn = document.getElementById('modalCloseBtn');
  const dismissBtn = document.getElementById('modalDismissBtn');
  const revealBtn = document.getElementById('btnRevealFile');
  const copyBtn = document.getElementById('btnCopyCmd');
  const powershellCmdText = document.getElementById('powershellCmdText');
  const modalStatus = document.getElementById('modalStatusText');

  function openModal() {
    if (modal) modal.style.display = 'flex';
  }
  function closeModal() {
    if (modal) modal.style.display = 'none';
  }

  if (closeBtn) closeBtn.addEventListener('click', closeModal);
  if (dismissBtn) dismissBtn.addEventListener('click', closeModal);
  if (modal) {
    modal.addEventListener('click', e => {
      if (e.target === modal) closeModal();
    });
  }

  if (revealBtn) {
    revealBtn.addEventListener('click', async () => {
      try {
        await fetch('/api/admin/open-folder', { method: 'POST' });
        revealBtn.textContent = 'Opened in File Explorer!';
        setTimeout(() => {
          revealBtn.innerHTML = `
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
            Open Project Folder in Explorer
          `;
        }, 3000);
      } catch (err) {
        console.warn('Could not open folder:', err);
      }
    });
  }

  if (copyBtn && powershellCmdText) {
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(powershellCmdText.textContent.trim()).then(() => {
        copyBtn.textContent = 'Copied!';
        copyBtn.classList.add('btn-primary');
        setTimeout(() => {
          copyBtn.textContent = 'Copy';
          copyBtn.classList.remove('btn-primary');
        }, 2000);
      });
    });
  }

  if (!dom.elevateBtn) return;

  dom.elevateBtn.addEventListener('click', async () => {
    openModal();
    pollElevatedServer();

    try {
      const resp = await fetch('/api/admin/elevate', { method: 'POST' });
      const data = await resp.json().catch(() => ({}));
      if (data.powershellCmd && powershellCmdText) {
        powershellCmdText.textContent = data.powershellCmd;
      }
    } catch (err) {
      console.warn('Elevation request returned:', err);
    }
  });
}

function pollElevatedServer() {
  let attempts = 0;
  const maxAttempts = 35; // ~50 seconds max

  const pollInterval = setInterval(async () => {
    attempts++;
    dom.elevateReconnectHint.textContent = `Attempting connection (${attempts}/${maxAttempts})...`;

    try {
      const resp = await fetch('/api/admin/status', { cache: 'no-store' });
      if (resp.ok) {
        const data = await resp.json();
        if (data.isAdmin) {
          clearInterval(pollInterval);
          state.isElevating = false;
          state.isAdmin = true;

          dom.elevateBanner.className = 'elevate-banner elevate-success';
          dom.elevateBannerText.innerHTML = '<strong>Administrator access active!</strong> Streaming real Windows Security event logs.';
          dom.elevateReconnectHint.textContent = 'Connected';

          dom.demoBanner.style.display = 'none';
          dom.adminBadge.style.display = 'inline-flex'; const m = document.getElementById('elevateModal'); if (m) m.style.display = 'none';

          // Re-establish real SSE connection
          connectSSE();

          setTimeout(() => {
            dom.elevateBanner.style.display = 'none';
          }, 4000);
          return;
        }
      }
    } catch (e) {
      // Server is currently restarting / shutting down old process
    }

    if (attempts >= maxAttempts) {
      clearInterval(pollInterval);
      state.isElevating = false;
      dom.elevateBanner.className = 'elevate-banner elevate-error';
      dom.elevateBannerText.innerHTML = 'Elevation timed out or was cancelled. Still running in demo mode.';
      dom.elevateReconnectHint.textContent = '';
      dom.elevateBtn.disabled = false;
      dom.elevateBtn.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true"><path d="M7 1L2 3.8v4.2c0 3.3 2.2 6.2 5 7 2.8-.8 5-3.7 5-7V3.8L7 1z" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M5 7l1.5 1.5L9 5.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <span>Enable Real Device Logs</span>
      `;
      setTimeout(() => {
        dom.elevateBanner.style.display = 'none';
      }, 5000);
      connectSSE();
    }
  }, 1500);
}

// ── Threat cards ─────────────────────────────────
function renderThreatCard(threat) {
  dom.threatsEmpty.style.display = 'none';
  const card = document.createElement('div');
  card.className = 'threat-card';
  card.dataset.sev = threat.severity;
  card.dataset.key = threat.type + '|' + threat.username + '|' + threat.ipAddress;
  card.tabIndex = 0;
  card.setAttribute('role', 'button');
  card.setAttribute('aria-label', `View details for threat: ${threat.type}`);
  const fillPct = Math.min(100, threat.score).toFixed(0);

  card.innerHTML = `
    <div class="threat-card-top">
      <span class="threat-card-type">${escHtml(threat.type.replace(/_/g,' '))}</span>
      <div class="threat-score-bar-wrap">
        <span class="threat-score-label">${fillPct}</span>
        <div class="threat-score-bar"><div class="threat-score-fill" style="width:${fillPct}%"></div></div>
      </div>
    </div>
    <div class="threat-desc">${escHtml(threat.description)}</div>
    <div class="threat-meta">
      ${threat.username ? `<div class="threat-meta-item"><span>User:</span> <code>${escHtml(threat.username)}</code></div>` : ''}
      ${threat.ipAddress ? `<div class="threat-meta-item"><span>IP:</span> <code>${escHtml(threat.ipAddress)}</code></div>` : ''}
      <div class="threat-meta-item"><span>Time:</span> ${escHtml(formatTimestamp(threat.detectedAt))}</div>
      <div class="threat-meta-item"><span>Events:</span> ${threat.contributingCount}</div>
    </div>
    <div class="threat-card-footer">
      <span class="threat-card-link">View full incident description &rarr;</span>
    </div>`;

  card.addEventListener('click', () => openThreatDetailModal(threat));
  card.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      openThreatDetailModal(threat);
    }
  });

  const existing = dom.threatsGrid.querySelector(`[data-key="${card.dataset.key}"]`);
  if (existing) {
    existing.replaceWith(card);
  } else {
    dom.threatsGrid.insertBefore(card, dom.threatsGrid.firstChild);
  }
  applyThreatSeverityFilter();
}

function openThreatDetailModal(threat) {
  if (!threat || !dom.threatDetailModal) return;

  const sev = threat.severity || 'UNKNOWN';
  const typeFormatted = (threat.type || 'THREAT').replace(/_/g, ' ');
  const fillPct = Math.min(100, threat.score || 0).toFixed(0);

  if (dom.threatModalTitle) dom.threatModalTitle.textContent = typeFormatted;
  if (dom.threatModalSeverityBadge) {
    dom.threatModalSeverityBadge.textContent = sev;
    dom.threatModalSeverityBadge.className = `sev-modal-badge sev-modal-badge--${sev}`;
  }

  if (dom.threatModalSubtitle) {
    if (threat.detectedAt) {
      dom.threatModalSubtitle.textContent = `Detected at ${formatTimestamp(threat.detectedAt)} (${formatTimestamp24(threat.detectedAt)} UTC)`;
    } else {
      dom.threatModalSubtitle.textContent = 'Incident Forensics & Threat Breakdown';
    }
  }

  const iconStroke = sev === 'CRITICAL' ? 'var(--sev-critical)' :
                     sev === 'HIGH'     ? 'var(--sev-high)' :
                     sev === 'MEDIUM'   ? 'var(--sev-medium)' : 'var(--sev-low)';

  if (dom.threatModalIcon) {
    dom.threatModalIcon.innerHTML = `
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="${iconStroke}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
        <line x1="12" y1="9" x2="12" y2="13"></line>
        <line x1="12" y1="17" x2="12.01" y2="17"></line>
      </svg>`;
  }

  let riskAnalysis = '';
  let remediationList = [];

  switch (threat.type) {
    case 'BRUTE_FORCE':
      riskAnalysis = 'Automated rapid authentication burst detected exceeding threshold limits. An adversary or automated tool is repeatedly submitting credentials to compromise valid account credentials.';
      remediationList = [
        `Temporarily or permanently block IP <strong>${escHtml(threat.ipAddress || 'origin')}</strong> at the network firewall / WAF.`,
        `Inspect target user account <strong>${escHtml(threat.username || 'targeted accounts')}</strong> for potential lockout or compromise.`,
        'Enforce Multi-Factor Authentication (MFA) and lock accounts after multiple consecutive failed attempts.'
      ];
      break;
    case 'REPEATED_LOGIN_FAILURE':
      riskAnalysis = 'Persistent failed login attempts observed across a sliding time window. This velocity profile suggests password guessing, spray attempts, or an improperly configured integration.';
      remediationList = [
        `Verify whether IP <strong>${escHtml(threat.ipAddress || 'origin')}</strong> belongs to an authorized internal host or unknown external address.`,
        'Audit recent authentication logs for common targeted account usernames.',
        'Consider enabling automated IP tarpitting or progressive authentication delays.'
      ];
      break;
    case 'UNAUTHORIZED_ACCESS':
      riskAnalysis = 'Access was explicitly denied to a protected resource, privileged endpoint, or critical system file. This pattern indicates unauthorized lateral movement or privilege escalation attempts.';
      remediationList = [
        `Review privileges and permissions assigned to <strong>${escHtml(threat.username || 'this user account')}</strong>.`,
        'Validate if access attempt was originating from an approved workstation or network zone.',
        'Check directory access control lists (ACLs) and security group memberships.'
      ];
      break;
    case 'ANOMALOUS_BEHAVIOR':
      riskAnalysis = 'Account authenticated from 3 or more distinct IP addresses in a condensed time window. This anomaly suggests stolen credentials, token hijacking, or simultaneous multi-location logons.';
      remediationList = [
        `Immediately verify identity of user <strong>${escHtml(threat.username || 'account')}</strong> and revoke active session tokens.`,
        'Require an immediate mandatory password reset with MFA validation.',
        'Inspect geolocation and ASN ownership of the contributing IP addresses.'
      ];
      break;
    default:
      riskAnalysis = 'Activity violated security detection baseline rules and generated a high-confidence threat notification.';
      remediationList = [
        'Review recent network traffic and process execution associated with this host.',
        'Correlate with system audit and authentication event streams.'
      ];
  }

  if (dom.threatModalBody) {
    dom.threatModalBody.innerHTML = `
      <div class="threat-desc-callout threat-desc-callout--${sev}">
        <div class="threat-desc-callout-label">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
          Full Threat Description
        </div>
        <div class="threat-desc-callout-text">${escHtml(threat.description)}</div>
      </div>

      <div class="threat-meta-grid">
        <div class="threat-meta-card">
          <span class="threat-meta-card-label">Source IP Address</span>
          <div class="threat-meta-card-val">
            ${threat.ipAddress ? `<code id="modalThreatIp" style="cursor:pointer;color:var(--color-accent);" title="Click to view IP forensic dossier">${escHtml(threat.ipAddress)} ↗</code>` : '<span style="color:var(--color-text-muted)">N/A (Multi-IP / Internal)</span>'}
          </div>
        </div>
        <div class="threat-meta-card">
          <span class="threat-meta-card-label">Target User Account</span>
          <div class="threat-meta-card-val">
            ${threat.username ? `<code id="modalThreatUser" style="cursor:pointer;color:var(--color-accent);" title="Click to view User forensic dossier">${escHtml(threat.username)} ↗</code>` : '<span style="color:var(--color-text-muted)">Unspecified / Multiple</span>'}
          </div>
        </div>
        <div class="threat-meta-card">
          <span class="threat-meta-card-label">Risk Severity &amp; Score</span>
          <div class="threat-meta-card-val">
            <span class="sev-modal-badge sev-modal-badge--${sev}">${sev}</span>
            <span style="font-size:0.8rem;color:var(--color-text-secondary);font-weight:600">${fillPct} / 100</span>
          </div>
        </div>
        <div class="threat-meta-card">
          <span class="threat-meta-card-label">Contributing Security Events</span>
          <div class="threat-meta-card-val">
            <span>${threat.contributingCount} correlated log entries</span>
          </div>
        </div>
      </div>

      <div class="threat-info-block">
        <div class="threat-info-title">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#2563EB" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <path d="M12 16v-4"></path>
            <path d="M12 8h.01"></path>
          </svg>
          Security Analysis &amp; Impact
        </div>
        <p class="threat-info-text">${riskAnalysis}</p>
      </div>

      <div class="threat-info-block">
        <div class="threat-info-title" style="color:var(--sev-critical);">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          </svg>
          Recommended SOC Remediation Steps
        </div>
        <ul class="threat-remediation-list">
          ${remediationList.map(item => `<li>${item}</li>`).join('')}
        </ul>
      </div>
    `;

    const modalIp = dom.threatModalBody.querySelector('#modalThreatIp');
    if (modalIp && threat.ipAddress) {
      modalIp.addEventListener('click', () => {
        closeThreatDetailModal();
        openDossier('ip', threat.ipAddress);
      });
    }
    const modalUser = dom.threatModalBody.querySelector('#modalThreatUser');
    if (modalUser && threat.username) {
      modalUser.addEventListener('click', () => {
        closeThreatDetailModal();
        openDossier('user', threat.username);
      });
    }
  }

  dom.threatDetailModal.style.display = 'flex';
}

function closeThreatDetailModal() {
  if (dom.threatDetailModal) {
    dom.threatDetailModal.style.display = 'none';
  }
}

function setupThreatModal() {
  if (dom.threatModalCloseBtn) dom.threatModalCloseBtn.addEventListener('click', closeThreatDetailModal);
  if (dom.threatModalDismissBtn) dom.threatModalDismissBtn.addEventListener('click', closeThreatDetailModal);
  if (dom.threatDetailModal) {
    dom.threatDetailModal.addEventListener('click', (e) => {
      if (e.target === dom.threatDetailModal) closeThreatDetailModal();
    });
  }
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && dom.threatDetailModal && dom.threatDetailModal.style.display !== 'none') {
      closeThreatDetailModal();
    }
  });
}

function updateThreatCount() {
  dom.threatCount.textContent = state.threats.length;
}

function flashThreatPanel() {
  const panel = document.getElementById('threatsPanel');
  if (!panel) return;
  panel.style.outline = '2px solid #DC2626';
  panel.style.outlineOffset = '2px';
  setTimeout(() => { panel.style.outline = ''; panel.style.outlineOffset = ''; }, 600);
}

// ── Log table ────────────────────────────────────
function renderTableRow(entry, prepend) {
  if (!matchesFilters(entry)) return;
  dom.logEmpty.style.display = 'none';

  const tr = document.createElement('tr');
  if (prepend) tr.className = 'new-row';
  tr.dataset.action = entry.action;
  tr.dataset.status = entry.statusCode;
  tr.dataset.ip     = entry.ipAddress;
  tr.dataset.user   = entry.username;
  tr.dataset.ts     = entry.timestamp;

  tr.innerHTML = `
    <td class="ts" title="${escHtml(formatTimestamp24(entry.timestamp))} (24h)">${escHtml(formatTimestamp(entry.timestamp))}</td>
    <td class="user" title="${entry.username ? 'Click to inspect ' + escHtml(entry.username) + ' forensic dossier' : ''}">${escHtml(entry.username || '—')}</td>
    <td class="ip" title="${entry.ipAddress ? 'Click to inspect ' + escHtml(entry.ipAddress) + ' forensic dossier' : ''}">${escHtml(entry.ipAddress || '—')}</td>
    <td><span class="action-badge action--${escHtml(entry.action)}">${escHtml(entry.action.replace(/_/g,' '))}</span></td>
    <td><span class="status-badge badge--${escHtml(entry.statusCode)}">${escHtml(entry.statusCode.replace(/_/g,' '))}</span></td>
  `;

  const userTd = tr.querySelector('td.user');
  if (userTd && entry.username) {
    userTd.addEventListener('click', (e) => {
      e.stopPropagation();
      openDossier('user', entry.username);
    });
  }

  const ipTd = tr.querySelector('td.ip');
  if (ipTd && entry.ipAddress) {
    ipTd.addEventListener('click', (e) => {
      e.stopPropagation();
      openDossier('ip', entry.ipAddress);
    });
  }

  if (prepend && dom.logTableBody.firstChild) {
    dom.logTableBody.insertBefore(tr, dom.logTableBody.firstChild);
  } else {
    dom.logTableBody.appendChild(tr);
  }

  // Cap DOM rows at 200 for smooth 60fps performance
  while (dom.logTableBody.children.length > 200) {
    dom.logTableBody.removeChild(dom.logTableBody.lastChild);
  }
}

function updateLogCount() {
  const visible = dom.logTableBody.querySelectorAll('tr').length;
  dom.logCount.textContent = visible;
}

function reFilterTable() {
  dom.logTableBody.innerHTML = '';
  const filtered = state.entries.filter(matchesFilters);
  if (filtered.length === 0) {
    dom.logEmpty.style.display = 'flex';
  } else {
    dom.logEmpty.style.display = 'none';
    filtered.slice(0, 150).forEach(e => renderTableRow(e, false));
  }
  updateLogCount();
}

function matchesFilters(e) {
  if (state.filterAction && e.action !== state.filterAction) return false;
  if (state.filterStatus && e.statusCode !== state.filterStatus) return false;
  if (state.filterIp) {
    const q = state.filterIp.toLowerCase();
    const ip = (e.ipAddress || '').toLowerCase();
    const user = (e.username || '').toLowerCase();
    if (!ip.includes(q) && !user.includes(q)) return false;
  }
  return true;
}

// ── Sorting ──────────────────────────────────────
function setupTableSorting() {
  const headers = dom.logTable.querySelectorAll('th.sortable');
  headers.forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.col;
      if (state.sortCol === col) {
        state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        state.sortCol = col;
        state.sortDir = 'desc';
      }
      headers.forEach(h => {
        h.removeAttribute('aria-sort');
        const icon = h.querySelector('.sort-icon');
        if (icon) icon.textContent = '';
      });
      th.setAttribute('aria-sort', state.sortDir === 'asc' ? 'ascending' : 'descending');
      const icon = th.querySelector('.sort-icon');
      if (icon) icon.textContent = state.sortDir === 'asc' ? ' ▲' : ' ▼';

      state.entries.sort((a, b) => {
        let va = a[col] || '';
        let vb = b[col] || '';
        const cmp = String(va).localeCompare(String(vb));
        return state.sortDir === 'asc' ? cmp : -cmp;
      });
      reFilterTable();
    });
  });
}

// ── Filters ──────────────────────────────────────
function setupFilters() {
  dom.filterAction.addEventListener('change', e => {
    state.filterAction = e.target.value;
    reFilterTable();
  });
  dom.filterStatus.addEventListener('change', e => {
    state.filterStatus = e.target.value;
    reFilterTable();
  });
  dom.filterIp.addEventListener('input', e => {
    state.filterIp = e.target.value.trim();
    reFilterTable();
  });

  // Threat severity filter buttons
  document.querySelectorAll('.sev-filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.sev-filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.sevFilter = btn.dataset.sev;
      applyThreatSeverityFilter();
    });
  });
}

function applyThreatSeverityFilter() {
  const cards = dom.threatsGrid.querySelectorAll('.threat-card');
  let visible = 0;
  cards.forEach(card => {
    const sev = card.dataset.sev;
    const show = state.sevFilter === 'ALL' || sev === state.sevFilter;
    card.style.display = show ? 'flex' : 'none';
    if (show) visible++;
  });
  dom.threatsEmpty.style.display = (visible === 0 && state.threats.length > 0) ? 'flex' : (state.threats.length === 0 ? 'flex' : 'none');
}

// ── File Analysis ────────────────────────────────
function setupFileAnalysis() {
  dom.filePanelToggle.addEventListener('click', () => {
    const open = !dom.filePanelBody.hidden;
    dom.filePanelBody.hidden = open;
    dom.filePanelToggle.setAttribute('aria-expanded', String(!open));
    dom.collapseArrow.classList.toggle('open', !open);
  });

  dom.dropZone.addEventListener('click', () => dom.fileInput.click());
  dom.browseLink.addEventListener('click', e => { e.stopPropagation(); dom.fileInput.click(); });

  dom.dropZone.addEventListener('dragover', e => { e.preventDefault(); dom.dropZone.classList.add('dragover'); });
  dom.dropZone.addEventListener('dragleave', () => dom.dropZone.classList.remove('dragover'));
  dom.dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dom.dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) handleFileUpload(e.dataTransfer.files[0]);
  });

  dom.fileInput.addEventListener('change', () => {
    if (dom.fileInput.files.length > 0) handleFileUpload(dom.fileInput.files[0]);
  });

  dom.analyzePasteBtn.addEventListener('click', handlePasteAnalysis);
}

async function handleFileUpload(file) {
  showFileLoading(true);
  const formData = new FormData();
  formData.append('file', file);
  try {
    const resp = await fetch('/api/analyze/upload', { method: 'POST', body: formData });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    renderAnalysisResults(data, file.name);
  } catch (err) {
    renderAnalysisError(`Upload failed: ${err.message}`);
  } finally {
    showFileLoading(false);
  }
}

async function handlePasteAnalysis() {
  const text = dom.pasteInput.value.trim();
  if (!text) return;
  showFileLoading(true);
  try {
    const resp = await fetch('/api/analyze/text', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: text,
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    renderAnalysisResults(data, 'Pasted text snippet');
  } catch (err) {
    renderAnalysisError(`Analysis failed: ${err.message}`);
  } finally {
    showFileLoading(false);
  }
}

function showFileLoading(show) {
  dom.fileLoading.style.display = show ? 'flex' : 'none';
  if (show) dom.analysisResults.style.display = 'none';
}

function renderAnalysisResults(data, source) {
  const formats = data.formatsDetected ? Object.keys(data.formatsDetected).join(', ') : 'Unknown';
  dom.analysisMeta.textContent = `${source} — ${data.entries ? data.entries.length : 0} entries, ${data.threats ? data.threats.length : 0} threats [Format: ${formats}]`;

  let html = '';

  if (data.threats && data.threats.length > 0) {
    html += `<div class="analysis-sub-panel">
      <div class="analysis-sub-title" style="font-weight:600;margin-bottom:8px;color:var(--sev-critical);">Threats Detected (${data.threats.length})</div>
      <div class="analysis-threats-list">`;
    data.threats.forEach(t => {
      const fillPct = Math.min(100, t.score).toFixed(0);
      html += `<div class="threat-card" data-sev="${escHtml(t.severity)}" style="width:auto;min-width:260px">
        <div class="threat-card-top">
          <span class="threat-card-type">${escHtml(t.type.replace(/_/g,' '))}</span>
          <div class="threat-score-bar-wrap">
            <span class="threat-score-label">${fillPct}</span>
            <div class="threat-score-bar"><div class="threat-score-fill" style="width:${fillPct}%"></div></div>
          </div>
        </div>
        <div class="threat-desc">${escHtml(t.description)}</div>
        <div class="threat-meta">
          ${t.username ? `<div class="threat-meta-item"><span>User:</span> <code>${escHtml(t.username)}</code></div>` : ''}
          ${t.ipAddress ? `<div class="threat-meta-item"><span>IP:</span> <code>${escHtml(t.ipAddress)}</code></div>` : ''}
          <div class="threat-meta-item"><span>Events:</span> ${t.contributingCount}</div>
        </div>
        <div class="threat-card-footer">
          <span class="threat-card-link">View full incident description &rarr;</span>
        </div>
      </div>`;
    });
    html += `</div></div>`;
  }

  if (data.entries && data.entries.length > 0) {
    html += `<div class="analysis-sub-panel" style="margin-top:12px">
      <div class="analysis-sub-title" style="font-weight:600;margin-bottom:8px;color:var(--color-text-primary);">Valid Entries (${data.entries.length})</div>
      <div class="table-wrapper" style="max-height:260px">
        <table class="log-table"><thead><tr>
          <th>Timestamp</th><th>User</th><th>IP</th><th>Action</th><th>Status</th>
        </tr></thead><tbody>`;
    data.entries.slice(0, 100).forEach(e => {
      html += `<tr>
        <td class="ts" title="${escHtml(formatTimestamp24(e.timestamp))} (24h)">${escHtml(formatTimestamp(e.timestamp))}</td>
        <td class="user">${escHtml(e.username || '—')}</td>
        <td class="ip">${escHtml(e.ipAddress || '—')}</td>
        <td><span class="action-badge action--${escHtml(e.action)}">${escHtml(e.action.replace(/_/g,' '))}</span></td>
        <td><span class="status-badge badge--${escHtml(e.statusCode)}">${escHtml(e.statusCode.replace(/_/g,' '))}</span></td>
      </tr>`;
    });
    if (data.entries.length > 100) {
      html += `<tr><td colspan="5" style="text-align:center;color:var(--color-text-muted);font-style:italic">+ ${data.entries.length - 100} more entries</td></tr>`;
    }
    html += `</tbody></table></div></div>`;
  }

  if (data.rejectedLines && data.rejectedLines.length > 0) {
    html += `<div class="analysis-sub-panel" style="margin-top:12px">
      <div class="analysis-sub-title" style="font-weight:600;margin-bottom:8px;color:var(--sev-high);">Rejected Lines (${data.rejectedLines.length})</div>
      <ul class="error-list">`;
    data.rejectedLines.slice(0, 20).forEach(err => {
      html += `<li class="error-item">
        <div class="error-line">Line ${err.lineNumber}</div>
        <div class="error-reason">${escHtml(err.reason)}</div>
        <div class="error-raw">${escHtml(err.rawLine)}</div>
      </li>`;
    });
    if (data.rejectedLines.length > 20) {
      html += `<li class="error-item" style="font-style:italic;color:var(--color-text-muted)">+ ${data.rejectedLines.length - 20} more rejected lines</li>`;
    }
    html += `</ul></div>`;
  }

  if (!html) {
    html = `<div class="empty-state"><div class="empty-state-text">No parseable entries found</div><div class="empty-state-sub">Check that the file matches a supported log format (.log, .txt, .evtx)</div></div>`;
  }

  dom.analysisContent.innerHTML = html;
  dom.analysisResults.style.display = 'block';

  if (data.threats && data.threats.length > 0) {
    const cards = dom.analysisContent.querySelectorAll('.threat-card');
    cards.forEach((card, idx) => {
      const threat = data.threats[idx];
      if (threat) {
        card.tabIndex = 0;
        card.setAttribute('role', 'button');
        card.setAttribute('aria-label', `View details for threat: ${threat.type}`);
        card.addEventListener('click', () => openThreatDetailModal(threat));
        card.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            openThreatDetailModal(threat);
          }
        });
      }
    });
  }
}

function renderAnalysisError(msg) {
  dom.analysisContent.innerHTML = `<div class="error-item"><div class="error-line">Analysis failed</div><div class="error-reason">${escHtml(msg)}</div></div>`;
  dom.analysisResults.style.display = 'block';
}

// ── Stream Controls ──────────────────────────────
function setupStreamControls() {
  dom.toggleBtn.addEventListener('click', () => {
    state.streaming = !state.streaming;
    dom.toggleText.textContent = state.streaming ? 'Pause' : 'Resume';
    dom.toggleBtn.classList.toggle('btn-primary', !state.streaming);
    dom.toggleBtn.classList.toggle('btn-secondary', state.streaming);
    if (state.streaming) {
      dom.liveIndicator.classList.remove('paused');
    } else {
      dom.liveIndicator.classList.add('paused');
    }
  });

  dom.clearBtn.addEventListener('click', () => {
    fetch('/api/history', { method: 'DELETE' }).catch(() => {});
    state.entries = [];
    state.threats = [];
    dom.logTableBody.innerHTML = '';
    dom.threatsGrid.innerHTML = '';
    dom.threatsGrid.appendChild(dom.threatsEmpty);
    dom.threatsEmpty.style.display = 'flex';
    dom.logEmpty.style.display = 'flex';
    updateThreatCount();
    updateLogCount();
  });
}

// ── Load persisted history on page load / refresh ───
async function loadHistory() {
  try {
    const resp = await fetch('/api/history');
    if (!resp.ok) return;
    const data = await resp.json();

    if (data.stats) {
      updateStats(data.stats);
    }

    if (data.entries && data.entries.length > 0) {
      state.entries = data.entries.slice(0, 500);
      dom.logTableBody.innerHTML = '';
      dom.logEmpty.style.display = 'none';
      state.entries.forEach(entry => {
        renderTableRow(entry, false);
      });
      updateLogCount();
    }

    if (data.threats && data.threats.length > 0) {
      dom.threatsEmpty.style.display = 'none';
      state.threats = data.threats;
      state.threats.slice().reverse().forEach(threat => {
        renderThreatCard(threat);
      });
      updateThreatCount();
    }
  } catch (err) {
    console.warn('Could not load history on startup:', err);
  }
}

// ── Initial admin status check ───────────────────
async function checkAdminStatus() {
  try {
    const resp = await fetch('/api/admin/status');
    if (resp.ok) {
      const data = await resp.json();
      state.isAdmin = data.isAdmin;
      if (data.isAdmin) {
        dom.adminBadge.style.display = 'inline-flex'; const m = document.getElementById('elevateModal'); if (m) m.style.display = 'none';
        dom.demoBanner.style.display = 'none';
      } else {
        dom.adminBadge.style.display = 'none';
        dom.demoBanner.style.display = 'flex';
        if (dom.elevateControls) {
          dom.elevateControls.style.display = data.canElevate ? 'block' : 'none';
        }
      }
    }
  } catch (err) {
    console.warn('Could not fetch admin status:', err);
  }
}

// ── Helpers ──────────────────────────────────────
function escHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function parseToDate(ts) {
  if (!ts) return null;
  let str = String(ts).trim();
  if (str.includes(' ') && !str.includes('T')) {
    str = str.replace(' ', 'T');
  }
  if (!str.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(str)) {
    str += 'Z';
  }
  const d = new Date(str);
  return isNaN(d.getTime()) ? null : d;
}

function formatTimestamp(ts) {
  if (!ts) return '—';
  try {
    const d = parseToDate(ts);
    if (!d) return String(ts).substring(0, 19);

    const pad = n => String(n).padStart(2, '0');
    const yyyy = d.getFullYear();
    const mm = pad(d.getMonth() + 1);
    const dd = pad(d.getDate());
    const hours = d.getHours();
    const minutes = pad(d.getMinutes());
    const seconds = pad(d.getSeconds());
    const ampm = hours >= 12 ? 'PM' : 'AM';
    const hours12 = pad(hours % 12 || 12);

    return `${yyyy}-${mm}-${dd} ${hours12}:${minutes}:${seconds} ${ampm}`;
  } catch (e) {
    return String(ts).substring(0, 19);
  }
}

function formatTimestamp24(ts) {
  if (!ts) return '—';
  try {
    const d = parseToDate(ts);
    if (!d) return String(ts).substring(0, 19);

    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  } catch (e) {
    return String(ts);
  }
}

function updateFooterTime() {
  const now = new Date().toLocaleTimeString();
  if (dom.footerStatus && state.sse && dom.sse.readyState === EventSource.OPEN) {
    dom.footerStatus.textContent = `${state.isAdmin ? 'Streaming live Windows Security event logs' : 'Streaming events (Demo mode)'} — Last heartbeat: ${now}`;
  }
}

// ── Forensic Dossier Drawer ───────────────────────
async function openDossier(type, value) {
  if (!value || value === '—' || value === 'N/A' || !dom.dossierDrawer) return;

  dom.dossierBadge.textContent = type === 'user' ? 'USER IDENTITY DOSSIER' : 'IP ADDRESS DOSSIER';
  dom.dossierTitle.textContent = value;
  dom.dossierBody.innerHTML = `
    <div class="loading-overlay" style="padding:40px 0;">
      <div class="spinner"></div>
      <span>Querying database &amp; correlating forensic history...</span>
    </div>
  `;

  dom.dossierDrawer.classList.add('open');
  dom.dossierDrawer.setAttribute('aria-hidden', 'false');
  if (dom.dossierBackdrop) dom.dossierBackdrop.style.display = 'block';

  try {
    const res = await fetch(`/api/dossier?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    renderDossierContent(data);
  } catch (err) {
    dom.dossierBody.innerHTML = `
      <div class="error-item">
        <div class="error-line">Forensic Lookup Error</div>
        <div class="error-reason">Could not load dossier for ${escHtml(value)}: ${escHtml(err.message)}</div>
      </div>
    `;
  }
}

function closeDossier() {
  if (dom.dossierDrawer) {
    dom.dossierDrawer.classList.remove('open');
    dom.dossierDrawer.setAttribute('aria-hidden', 'true');
  }
  if (dom.dossierBackdrop) {
    dom.dossierBackdrop.style.display = 'none';
  }
}

function setupDossier() {
  if (dom.dossierCloseBtn) {
    dom.dossierCloseBtn.addEventListener('click', closeDossier);
  }
  if (dom.dossierBackdrop) {
    dom.dossierBackdrop.addEventListener('click', closeDossier);
  }
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && dom.dossierDrawer && dom.dossierDrawer.classList.contains('open')) {
      closeDossier();
    }
  });
}

function renderDossierContent(dossier) {
  const isUser = dossier.type === 'user';
  const total = dossier.totalEvents || 0;
  const fails = dossier.failureCount || 0;
  const successes = dossier.successCount || 0;
  const failRate = total > 0 ? Math.round((fails / total) * 100) : 0;
  const threats = dossier.threats || [];
  const logs = dossier.recentLogs || [];

  let threatsHtml = '';
  if (threats.length > 0) {
    threatsHtml = `
      <div>
        <div style="font-size:0.75rem;font-weight:700;color:var(--sev-critical);text-transform:uppercase;margin-bottom:8px;display:flex;align-items:center;gap:6px;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path></svg>
          Correlated Threats (${threats.length})
        </div>
        <div style="display:flex;flex-direction:column;gap:6px;">
          ${threats.map(t => `
            <div style="background:var(--sev-critical-bg);border:1px solid var(--sev-critical-border);border-radius:var(--radius-sm);padding:8px 10px;font-size:0.75rem;">
              <div style="display:flex;justify-content:space-between;font-weight:700;color:var(--sev-critical);">
                <span>${escHtml(t.type.replace(/_/g, ' '))}</span>
                <span class="sev-badge sev-badge--${escHtml(t.severity)}">${escHtml(t.severity)}</span>
              </div>
              <div style="color:var(--color-text-secondary);margin-top:2px;">${escHtml(t.description)}</div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  let logsHtml = '';
  if (logs.length > 0) {
    logsHtml = `
      <div>
        <div style="font-size:0.75rem;font-weight:700;color:var(--color-text-secondary);text-transform:uppercase;margin-bottom:8px;">
          Recent Ingested Activity (${logs.length})
        </div>
        <div class="dossier-timeline-list">
          ${logs.slice(0, 15).map(l => `
            <div class="dossier-log-row">
              <div>
                <span style="font-weight:600;color:var(--color-text-primary);">${escHtml(isUser ? (l.ipAddress || 'Internal') : (l.username || 'System'))}</span>
                <span style="font-size:0.7rem;color:var(--color-text-muted);display:block;">${escHtml(formatTimestamp(l.timestamp))}</span>
              </div>
              <div style="display:flex;gap:6px;align-items:center;">
                <span class="action-badge action--${escHtml(l.action)}">${escHtml(l.action.replace(/_/g,' '))}</span>
                <span class="status-badge badge--${escHtml(l.statusCode)}">${escHtml(l.statusCode.replace(/_/g,' '))}</span>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  } else {
    logsHtml = `<div class="empty-state" style="padding:20px 0;"><div class="empty-state-text">No activity records logged</div></div>`;
  }

  dom.dossierBody.innerHTML = `
    <div class="dossier-stat-grid">
      <div class="dossier-stat-card">
        <div class="dossier-stat-card-label">Total Events</div>
        <div class="dossier-stat-card-val">${total}</div>
      </div>
      <div class="dossier-stat-card">
        <div class="dossier-stat-card-label">Threat Incidents</div>
        <div class="dossier-stat-card-val" style="color:${threats.length > 0 ? 'var(--sev-critical)' : 'inherit'}">${threats.length}</div>
      </div>
      <div class="dossier-stat-card">
        <div class="dossier-stat-card-label">Auth Failures</div>
        <div class="dossier-stat-card-val" style="color:${fails > 0 ? 'var(--sev-high)' : 'inherit'}">${fails}</div>
      </div>
      <div class="dossier-stat-card">
        <div class="dossier-stat-card-label">Failure Rate</div>
        <div class="dossier-stat-card-val">${failRate}%</div>
      </div>
    </div>

    <div class="dossier-action-bar">
      <button class="btn btn-secondary btn-sm" id="dossierFilterBtn" style="flex:1;">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon></svg>
        Filter Table to this ${isUser ? 'User' : 'IP'}
      </button>
      <button class="btn btn-outline btn-sm" id="dossierCopyBtn" title="Copy entity name">
        Copy
      </button>
    </div>

    ${threatsHtml}
    ${logsHtml}
  `;

  const filterBtn = document.getElementById('dossierFilterBtn');
  if (filterBtn) {
    filterBtn.addEventListener('click', () => {
      if (isUser) {
        dom.filterIp.value = dossier.value;
        state.filterIp = dossier.value;
      } else {
        dom.filterIp.value = dossier.value;
        state.filterIp = dossier.value;
      }
      reFilterTable();
      closeDossier();
    });
  }

  const copyBtn = document.getElementById('dossierCopyBtn');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(dossier.value).then(() => {
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
      });
    });
  }
}

// ── CSV & Executive Incident Report Export ─────────
function setupExportFeatures() {
  if (dom.exportCsvBtn) {
    dom.exportCsvBtn.addEventListener('click', () => {
      window.location.href = '/api/export/csv';
    });
  }

  if (dom.exportReportBtn) {
    dom.exportReportBtn.addEventListener('click', openReportModal);
  }

  if (dom.reportModalCloseBtn) {
    dom.reportModalCloseBtn.addEventListener('click', closeReportModal);
  }
  if (dom.reportModalDismissBtn) {
    dom.reportModalDismissBtn.addEventListener('click', closeReportModal);
  }
  if (dom.reportPrintBtn) {
    dom.reportPrintBtn.addEventListener('click', () => {
      window.print();
    });
  }
  if (dom.reportModal) {
    dom.reportModal.addEventListener('click', (e) => {
      if (e.target === dom.reportModal) closeReportModal();
    });
  }
}

function closeReportModal() {
  if (dom.reportModal) dom.reportModal.style.display = 'none';
}

function openReportModal() {
  if (!dom.reportModal || !dom.reportModalContent) return;

  const now = new Date();
  const dateStr = now.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const timeStr = now.toLocaleTimeString('en-US', { hour12: true });

  const totalEvents = state.totalEvents || state.entries.length;
  const totalThreats = state.threats.length;
  const critCount = state.threats.filter(t => t.severity === 'CRITICAL').length;
  const highCount = state.threats.filter(t => t.severity === 'HIGH').length;
  const medCount = state.threats.filter(t => t.severity === 'MEDIUM').length;

  const ipCounts = {};
  const userCounts = {};
  state.entries.forEach(e => {
    if (e.ipAddress) ipCounts[e.ipAddress] = (ipCounts[e.ipAddress] || 0) + 1;
    if (e.username) userCounts[e.username] = (userCounts[e.username] || 0) + 1;
  });

  const topIps = Object.entries(ipCounts).sort((a,b) => b[1] - a[1]).slice(0, 5);
  const topUsers = Object.entries(userCounts).sort((a,b) => b[1] - a[1]).slice(0, 5);

  let threatsTableRows = '';
  if (state.threats.length > 0) {
    threatsTableRows = state.threats.map(t => `
      <tr>
        <td style="padding:8px 10px;border-bottom:1px solid #E2E8F0;font-size:0.76rem;font-weight:600;">
          <span class="sev-badge sev-badge--${escHtml(t.severity)}">${escHtml(t.severity)}</span>
        </td>
        <td style="padding:8px 10px;border-bottom:1px solid #E2E8F0;font-size:0.78rem;font-weight:600;">${escHtml(t.type.replace(/_/g, ' '))}</td>
        <td style="padding:8px 10px;border-bottom:1px solid #E2E8F0;font-size:0.76rem;font-family:var(--font-mono);">${escHtml(t.ipAddress || '—')}</td>
        <td style="padding:8px 10px;border-bottom:1px solid #E2E8F0;font-size:0.76rem;font-family:var(--font-mono);">${escHtml(t.username || '—')}</td>
        <td style="padding:8px 10px;border-bottom:1px solid #E2E8F0;font-size:0.74rem;color:#475569;">${escHtml(t.description)}</td>
      </tr>
    `).join('');
  } else {
    threatsTableRows = `<tr><td colspan="5" style="text-align:center;padding:16px;color:#64748B;">No threat incidents detected during this monitoring period.</td></tr>`;
  }

  dom.reportModalContent.innerHTML = `
    <div class="report-briefing-header">
      <div>
        <div class="report-brand-title">LogSentinel SOC Incident Briefing</div>
        <div class="report-brand-sub">Real-Time Threat Detection &amp; Forensic Audit Record</div>
      </div>
      <div class="report-meta-box">
        <div><strong>Date:</strong> ${dateStr} at ${timeStr}</div>
        <div><strong>Status:</strong> ${state.isAdmin ? 'Live Device Auditing (Admin)' : 'Live Event Streaming'}</div>
        <div><strong>Classification:</strong> RESTRICTED / INTERNAL SOC USE</div>
      </div>
    </div>

    <div class="report-section-title">Executive Summary</div>
    <div class="report-kpi-summary">
      <div class="report-kpi-box">
        <div class="report-kpi-box-num">${totalEvents}</div>
        <div class="report-kpi-box-label">Events Audited</div>
      </div>
      <div class="report-kpi-box">
        <div class="report-kpi-box-num" style="color:#DC2626;">${totalThreats}</div>
        <div class="report-kpi-box-label">Threats Detected</div>
      </div>
      <div class="report-kpi-box">
        <div class="report-kpi-box-num" style="color:#DC2626;">${critCount}</div>
        <div class="report-kpi-box-label">Critical Severity</div>
      </div>
      <div class="report-kpi-box">
        <div class="report-kpi-box-num" style="color:#EA580C;">${state.totalFailures}</div>
        <div class="report-kpi-box-label">Auth Failures</div>
      </div>
    </div>

    <div class="report-section-title">Detected Threat Findings &amp; Mitigations</div>
    <table style="width:100%;border-collapse:collapse;margin-bottom:20px;border:1px solid #CBD5E1;border-radius:6px;overflow:hidden;">
      <thead>
        <tr style="background:#F1F5F9;text-align:left;font-size:0.72rem;color:#475569;text-transform:uppercase;">
          <th style="padding:8px 10px;border-bottom:1px solid #CBD5E1;">Severity</th>
          <th style="padding:8px 10px;border-bottom:1px solid #CBD5E1;">Threat Vector</th>
          <th style="padding:8px 10px;border-bottom:1px solid #CBD5E1;">Source IP</th>
          <th style="padding:8px 10px;border-bottom:1px solid #CBD5E1;">User Target</th>
          <th style="padding:8px 10px;border-bottom:1px solid #CBD5E1;">Description</th>
        </tr>
      </thead>
      <tbody>
        ${threatsTableRows}
      </tbody>
    </table>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;">
      <div>
        <div class="report-section-title" style="margin-top:0;">Top Security Event Source IPs</div>
        <ul style="list-style:none;padding:0;margin:0;font-size:0.78rem;">
          ${topIps.length > 0 ? topIps.map(([ip, cnt]) => `
            <li style="display:flex;justify-content:space-between;padding:5px 8px;border-bottom:1px solid #F1F5F9;">
              <code style="font-family:var(--font-mono);">${escHtml(ip)}</code>
              <span style="font-weight:600;color:#475569;">${cnt} events</span>
            </li>
          `).join('') : '<li style="color:#94A3B8;">No IP activity logged yet</li>'}
        </ul>
      </div>
      <div>
        <div class="report-section-title" style="margin-top:0;">Top Targeted User Identities</div>
        <ul style="list-style:none;padding:0;margin:0;font-size:0.78rem;">
          ${topUsers.length > 0 ? topUsers.map(([usr, cnt]) => `
            <li style="display:flex;justify-content:space-between;padding:5px 8px;border-bottom:1px solid #F1F5F9;">
              <code style="font-family:var(--font-mono);">${escHtml(usr)}</code>
              <span style="font-weight:600;color:#475569;">${cnt} events</span>
            </li>
          `).join('') : '<li style="color:#94A3B8;">No user activity logged yet</li>'}
        </ul>
      </div>
    </div>

    <div class="report-section-title">Mandatory SOC Remediation Checklist</div>
    <div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;padding:12px 16px;font-size:0.78rem;line-height:1.6;color:#334155;">
      <div>&#9633; <strong>Boundary Defense:</strong> Inspect firewall logs and temporarily block high-frequency failed authentication origin IPs.</div>
      <div>&#9633; <strong>Identity Audit:</strong> Verify multi-factor authentication (MFA) enforcement on flagged accounts (Administrator, test, service accounts).</div>
      <div>&#9633; <strong>Session Invalidation:</strong> Force immediate token expiration and credential change for accounts impacted by anomalous credential reuse.</div>
      <div>&#9633; <strong>Evidence Archival:</strong> Retain raw CSV logs exported from this session in tamper-evident cold storage for regulatory compliance.</div>
    </div>
  `;

  dom.reportModal.style.display = 'flex';
}

// ── Init ─────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  setupTableSorting();
  setupFilters();
  setupFileAnalysis();
  setupStreamControls();
  setupElevation();
  setupThreatModal();
  setupDossier();
  setupExportFeatures();
  initVelocityChart();
  checkAdminStatus();
  loadHistory();
  connectSSE();
});