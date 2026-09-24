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

  statEventsVal:   document.getElementById('statEventsVal'),
  statThreatsVal:  document.getElementById('statThreatsVal'),
  statFailuresVal: document.getElementById('statFailuresVal'),
  statBufferVal:   document.getElementById('statBufferVal'),

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
};

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
      renderTableRow(entry, true);
      updateLogCount();
    } catch (err) { console.error('Error parsing log-entry:', err); }
  });

  es.addEventListener('threat', e => {
    if (!state.streaming) return;
    try {
      const threat = JSON.parse(e.data);
      state.threats.unshift(threat);
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
    </div>`;

  const existing = dom.threatsGrid.querySelector(`[data-key="${card.dataset.key}"]`);
  if (existing) {
    existing.replaceWith(card);
  } else {
    dom.threatsGrid.insertBefore(card, dom.threatsGrid.firstChild);
  }
  applyThreatSeverityFilter();
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
    <td class="user">${escHtml(entry.username || '—')}</td>
    <td class="ip">${escHtml(entry.ipAddress || '—')}</td>
    <td><span class="action-badge action--${escHtml(entry.action)}">${escHtml(entry.action.replace(/_/g,' '))}</span></td>
    <td><span class="status-badge badge--${escHtml(entry.statusCode)}">${escHtml(entry.statusCode.replace(/_/g,' '))}</span></td>
  `;

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
    const resp = await fetch('/api/analyze/paste', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawText: text }),
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

// ── Init ─────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  setupTableSorting();
  setupFilters();
  setupFileAnalysis();
  setupStreamControls();
  setupElevation();
  checkAdminStatus();
  connectSSE();
});