/**
 * APK Security Studio — Main Application Logic
 * SPA controller: file tree, editor tabs, scan findings, patches, AI chat, console
 */

// ─── State ────────────────────────────────────────────────────────────────────
const state = {
  projectId: null,
  apkName: null,
  openTabs: [],           // [{path, name, ext, modified}]
  activeTab: null,
  scanFindings: {},
  patchTemplates: {},
  socket: null,
  settings: {
    ai_provider: 'ollama',
    ai_model: 'mistral',
    api_key: '',
    custom_url: '',
    auto_sign: true,
    auto_scan: true,
  },
  pendingPatch: null,     // {templateId, results} awaiting confirm
  consoleCollapsed: false,
};

// ─── DOM Refs ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const dom = {
  loadingScreen:   $('loading-screen'),
  app:             $('app'),
  btnImport:       $('btn-import'),
  btnScan:         $('btn-scan'),
  btnBuild:        $('btn-build'),
  btnSaveFile:     $('btn-save-file'),
  btnSettings:     $('btn-settings'),
  btnRefreshTree:  $('btn-refresh-tree'),
  btnCollapseTree: $('btn-collapse-tree'),
  dropZone:        $('drop-zone'),
  fileTree:        $('file-tree'),
  apkInfo:         $('apk-info'),
  infoPkg:         $('info-package'),
  infoVer:         $('info-version'),
  infoSdk:         $('info-sdk'),
  infoDebuggable:  $('info-debuggable'),
  infoCleartext:   $('info-cleartext'),
  editorWelcome:   $('editor-welcome'),
  tabBar:          $('tab-bar'),
  monacoEl:        $('monaco-editor'),
  contextMenu:     $('context-menu'),
  breadcrumb:      $('project-breadcrumb'),
  chipTools:       $('chip-tools'),
  chipAI:          $('chip-ai'),
  aiProvider:      $('ai-provider'),
  aiModel:         $('ai-model'),
  aiUrl:           $('ai-url'),
  aiKey:           $('ai-key'),
  btnRefreshModels:$('btn-refresh-models'),
  findingsList:    $('findings-list'),
  findingsBadge:   $('findings-badge'),
  actionButtons:   $('action-buttons'),
  abPatchAll:      $('ab-patch-all'),
  abReviewEach:    $('ab-review-each'),
  abGenFrida:      $('ab-gen-frida'),
  abAiAnalyze:     $('ab-ai-analyze'),
  chatMessages:    $('chat-messages'),
  chatInput:       $('chat-input'),
  btnSendChat:     $('btn-send-chat'),
  btnClearChat:    $('btn-clear-chat'),
  consoleOutput:   $('console-output'),
  fridaOutput:     $('frida-output'),
  diffOutput:      $('diff-output'),
  btnClearConsole: $('btn-clear-console'),
  btnToggleConsole:$('btn-toggle-console'),
  btnCopyFrida:    $('btn-copy-frida'),
  fileInput:       $('file-input'),
  toastContainer:  $('toast-container'),
  consoleStrip:    $('console-strip'),

  // Modals
  modalSettings:   $('modal-settings'),
  modalPatch:      $('modal-patch'),
  modalFrida:      $('modal-frida'),
  patchModalTitle: $('patch-modal-title'),
  patchModalDesc:  $('patch-modal-desc'),
  patchDiffViewer: $('patch-diff-viewer'),
  btnConfirmPatch: $('btn-confirm-patch'),
  settingsProvider:$('settings-provider'),
  settingsModel:   $('settings-model'),
  settingsKey:     $('settings-key'),
  optAutoSign:     $('opt-auto-sign'),
  optAutoScan:     $('opt-auto-scan'),
  btnSaveSettings: $('btn-save-settings'),
  fridaClass:      $('frida-class'),
  fridaMethod:     $('frida-method'),
  fridaReturn:     $('frida-return'),
  fridaOutputModal:$('frida-output-modal'),
  btnGenFridaCustom:$('btn-gen-frida-custom'),
  btnCopyFridaModal:$('btn-copy-frida-modal'),
  btnSendToConsoleFrida: $('btn-send-to-console-frida'),
};

// ─── Init ─────────────────────────────────────────────────────────────────────
async function init() {
  // Fade out loading screen
  setTimeout(() => {
    dom.loadingScreen.classList.add('fade-out');
    dom.app.classList.remove('hidden');
    setTimeout(() => { dom.loadingScreen.style.display = 'none'; }, 600);
  }, 1200);

  // Load settings
  loadSettings();

  // Init WebSocket
  initSocket();

  // Check tools
  await checkTools();

  // Load patch templates
  try {
    state.patchTemplates = await API.getTemplates();
  } catch (e) { console.warn('Templates load failed:', e); }

  // Bind all events
  bindEvents();

  // Resize handles
  initResizeHandles();

  // Keyboard shortcuts
  initKeyboardShortcuts();

  console.log('[APK Studio] Application initialized');
}

// ─── WebSocket ────────────────────────────────────────────────────────────────
function initSocket() {
  if (typeof io === 'undefined') {
    console.warn('[APK Studio] Socket.IO not available — real-time logs disabled.');
    return;
  }
  state.socket = io({ transports: ['websocket', 'polling'] });

  state.socket.on('connect', () => {
    console.log('[Socket] Connected');
  });

  state.socket.on('console_log', ({ message, timestamp }) => {
    appendConsole(message, timestamp);
  });

  state.socket.on('decode_complete', ({ success, manifest }) => {
    if (success) {
      toast('APK decoded successfully!', 'success');
      if (manifest) updateManifestInfo(manifest);
      loadFileTree();
      if (state.settings.auto_scan && state.projectId) {
        setTimeout(() => runSecurityScan(), 500);
      }
    } else {
      toast('Decode failed. Check console for errors.', 'error');
    }
    enableToolbarButtons();
  });

  state.socket.on('scan_complete', ({ findings, total }) => {
    state.scanFindings = findings;
    renderFindings(findings);
    toast(`Scan complete: ${total} findings`, total > 0 ? 'warn' : 'success');
    dom.actionButtons.classList.remove('hidden');
    dom.findingsBadge.classList.add('pulse');
    setTimeout(() => dom.findingsBadge.classList.remove('pulse'), 5000);
  });

  state.socket.on('build_complete', ({ success, signed_apk, error }) => {
    if (success) {
      const dlUrl = API.downloadURL(state.projectId, signed_apk);
      const msg = `✅ Build complete! <a href="${dlUrl}" class="dl-link" download>Download ${signed_apk}</a>`;
      appendConsoleHTML(msg, 'success');
      toast('APK built and signed!', 'success');
    } else {
      toast(`Build failed: ${error}`, 'error');
    }
  });

  state.socket.on('ai_response', ({ response, context_file }) => {
    removeTypingIndicator();
    appendChatMessage('ai', response);
  });

  state.socket.on('disconnect', () => {
    console.warn('[Socket] Disconnected');
  });
}

// ─── Tool Health Check ────────────────────────────────────────────────────────
async function checkTools() {
  try {
    const { tools } = await API.health();
    const hasJava = tools.java;
    const hasApktool = tools.apktool;
    const ok = hasJava && hasApktool;

    const dot = dom.chipTools.querySelector('.status-dot');
    dot.className = 'status-dot ' + (ok ? 'dot-ok' : (hasJava || hasApktool ? 'dot-warn' : 'dot-err'));
    dom.chipTools.title = `Java: ${hasJava ? '✓' : '✗'} | apktool: ${hasApktool ? '✓' : '✗'} | ADB: ${tools.adb ? '✓' : '✗'}`;

    if (!hasJava) toast('Java not found in PATH. Build features disabled.', 'error');
    else if (!hasApktool) toast('apktool.jar not found.', 'warn');
  } catch (e) {
    const dot = dom.chipTools.querySelector('.status-dot');
    dot.className = 'status-dot dot-err';
    toast('Cannot connect to backend server.', 'error');
  }
}

// ─── Events ───────────────────────────────────────────────────────────────────
function bindEvents() {
  // Import APK
  dom.btnImport.addEventListener('click', () => dom.fileInput.click());
  dom.fileInput.addEventListener('change', (e) => handleFileSelect(e.target.files[0]));

  // Drop zone
  dom.dropZone.addEventListener('click', () => dom.fileInput.click());
  document.addEventListener('dragover', (e) => { e.preventDefault(); dom.dropZone.classList.add('drag-over'); });
  document.addEventListener('dragleave', () => dom.dropZone.classList.remove('drag-over'));
  document.addEventListener('drop', (e) => {
    e.preventDefault();
    dom.dropZone.classList.remove('drag-over');
    const f = e.dataTransfer.files[0];
    if (f && f.name.endsWith('.apk')) handleFileSelect(f);
    else if (f) toast('Please drop an .apk file', 'error');
  });

  // Toolbar buttons
  dom.btnScan.addEventListener('click', runSecurityScan);
  dom.btnBuild.addEventListener('click', buildAPK);
  dom.btnSaveFile.addEventListener('click', saveCurrentFile);
  dom.btnSettings.addEventListener('click', () => openModal('settings'));
  dom.btnRefreshTree.addEventListener('click', loadFileTree);

  // AI Panel
  dom.aiProvider.addEventListener('change', () => fetchModels());
  dom.btnRefreshModels.addEventListener('click', fetchModels);
  dom.btnSendChat.addEventListener('click', sendChatMessage);
  dom.chatInput.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChatMessage(); } });
  dom.btnClearChat.addEventListener('click', () => {
    dom.chatMessages.innerHTML = '<div class="chat-msg chat-msg-system"><div class="chat-bubble">Chat cleared.</div></div>';
  });

  // Action buttons
  dom.abPatchAll.addEventListener('click', patchAllFindings);
  dom.abReviewEach.addEventListener('click', reviewFindingsOneByOne);
  dom.abGenFrida.addEventListener('click', generateFridaFromScan);
  dom.abAiAnalyze.addEventListener('click', () => sendAIAnalyze());

  // Console
  dom.btnClearConsole.addEventListener('click', () => { dom.consoleOutput.innerHTML = ''; });
  dom.btnToggleConsole.addEventListener('click', toggleConsole);
  dom.btnCopyFrida.addEventListener('click', () => copyToClipboard(dom.fridaOutput.innerText));

  // Console tabs
  document.querySelectorAll('.console-tab').forEach(tab => {
    tab.addEventListener('click', () => switchConsoleTab(tab.dataset.tab));
  });

  // Modal closes
  document.querySelectorAll('[data-modal]').forEach(btn => {
    btn.addEventListener('click', () => closeModal(btn.dataset.modal));
  });
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        const id = overlay.id.replace('modal-', '');
        closeModal(id);
      }
    });
  });

  // Settings save
  dom.btnSaveSettings.addEventListener('click', saveSettings);

  // Patch confirm
  dom.btnConfirmPatch.addEventListener('click', confirmPatch);

  // Frida generator
  dom.btnGenFridaCustom.addEventListener('click', generateCustomFrida);
  dom.btnCopyFridaModal.addEventListener('click', () => copyToClipboard(dom.fridaOutputModal.textContent));
  dom.btnSendToConsoleFrida.addEventListener('click', () => {
    const script = dom.fridaOutputModal.textContent;
    showFridaScript(script);
    closeModal('frida');
    switchConsoleTab('frida');
    toast('Frida script sent to console', 'info');
  });

  // Context menu
  window.addEventListener('editor-context-menu', (e) => showContextMenu(e.detail));
  document.addEventListener('click', hideContextMenu);
  dom.contextMenu.addEventListener('click', (e) => {
    const item = e.target.closest('.ctx-item');
    if (item) handleContextAction(item.dataset.action);
  });

  // Editor save
  window.addEventListener('editor-save', saveCurrentFile);
}

// ─── File Import & Decode ─────────────────────────────────────────────────────
async function handleFileSelect(file) {
  if (!file) return;
  if (!file.name.endsWith('.apk')) { toast('Please select an .apk file', 'error'); return; }

  appendConsole(`[*] Uploading ${file.name} (${formatBytes(file.size)})...`);
  toast('Uploading APK...', 'info');

  const settings = getAISettings();
  try {
    const result = await API.uploadAPK(file, settings, (pct) => {
      appendConsole(`[*] Upload: ${pct}%`);
    });

    state.projectId = result.project_id;
    state.apkName = result.apk_name;

    appendConsole(`[+] Upload complete. Project ID: ${result.project_id}`);
    toast('Upload complete. Decoding APK...', 'info');

    updateBreadcrumb(file.name, result.project_id);
    dom.dropZone.classList.add('hidden');
    dom.fileTree.classList.remove('hidden');
    dom.apkInfo.classList.remove('hidden');
    dom.btnScan.disabled = false;
    dom.btnBuild.disabled = false;

    // Trigger decode
    await API.decode(state.projectId);
    appendConsole('[*] Decoding in progress...');

  } catch (e) {
    toast(`Upload failed: ${e.message}`, 'error');
    appendConsole(`[-] Upload error: ${e.message}`, 'error');
  }
}

// ─── File Tree ────────────────────────────────────────────────────────────────
async function loadFileTree() {
  if (!state.projectId) return;
  try {
    const tree = await API.getTree(state.projectId);
    renderFileTree(tree, dom.fileTree);
  } catch (e) {
    appendConsole(`[-] Tree load failed: ${e.message}`, 'error');
  }
}

function renderFileTree(node, container, depth = 0) {
  if (depth === 0) container.innerHTML = '';

  if (node.is_dir) {
    const children = node.children || [];
    if (depth === 0) {
      // Render root children directly
      children.forEach(child => renderFileTree(child, container, depth + 1));
      return;
    }

    const el = document.createElement('div');
    const ext = '';
    el.className = 'tree-item tree-dir';
    el.innerHTML = `
      ${indent(depth)}
      <span class="tree-arrow">▶</span>
      <span class="tree-icon">${dirIcon()}</span>
      <span class="tree-name">${escHtml(node.name)}</span>
    `;

    const childContainer = document.createElement('div');
    childContainer.className = 'tree-children';

    el.addEventListener('click', (e) => {
      e.stopPropagation();
      const arrow = el.querySelector('.tree-arrow');
      const isOpen = childContainer.classList.toggle('open');
      arrow.classList.toggle('open', isOpen);
    });

    container.appendChild(el);
    container.appendChild(childContainer);
    children.forEach(child => renderFileTree(child, childContainer, depth + 1));

  } else {
    const ext = node.ext || '';
    const el = document.createElement('div');
    el.className = `tree-item ext-${ext.replace('.', '')}`;
    el.dataset.path = node.rel;
    el.innerHTML = `
      ${indent(depth)}
      <span class="tree-arrow" style="visibility:hidden">▶</span>
      <span class="tree-icon">${fileIcon(ext)}</span>
      <span class="tree-name" title="${escHtml(node.rel)}">${escHtml(node.name)}</span>
    `;

    el.addEventListener('click', (e) => {
      e.stopPropagation();
      document.querySelectorAll('.tree-item.selected').forEach(i => i.classList.remove('selected'));
      el.classList.add('selected');
      openFileTab(node.rel, node.name, ext);
    });

    container.appendChild(el);
  }
}

function indent(depth) {
  return `<span class="tree-indent" style="width:${(depth - 1) * 16}px"></span>`;
}

function dirIcon() {
  return `<svg width="14" height="14" viewBox="0 0 24 24" fill="#fbbf24" stroke="none"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>`;
}

function fileIcon(ext) {
  const colors = { '.smali': '#67e8f9', '.java': '#fde68a', '.xml': '#86efac', '.so': '#fca5a5', '.dex': '#c4b5fd' };
  const c = colors[ext] || '#94a3b8';
  return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`;
}

// ─── Editor Tabs ──────────────────────────────────────────────────────────────
async function openFileTab(relPath, name, ext) {
  // Check if already open
  const existing = state.openTabs.find(t => t.path === relPath);
  if (existing) {
    setActiveTab(relPath);
    return;
  }

  try {
    const data = await API.readFile(state.projectId, relPath);
    if (data.error) { toast(data.error, 'error'); return; }

    state.openTabs.push({ path: relPath, name, ext, modified: false, content: data.content });
    renderTabBar();
    setActiveTab(relPath);
    dom.btnSaveFile.disabled = false;
  } catch (e) {
    toast(`Cannot open file: ${e.message}`, 'error');
  }
}

function renderTabBar() {
  dom.tabBar.innerHTML = '';
  state.openTabs.forEach(tab => {
    const el = document.createElement('div');
    el.className = `tab ${tab.path === state.activeTab ? 'active' : ''}`;
    el.dataset.path = tab.path;
    el.innerHTML = `
      <span class="tab-name">${escHtml(tab.name)}${tab.modified ? ' •' : ''}</span>
      <span class="tab-close" data-closetab="${tab.path}">✕</span>
    `;
    el.addEventListener('click', (e) => {
      if (e.target.dataset.closetab) {
        closeTab(e.target.dataset.closetab);
      } else {
        setActiveTab(tab.path);
      }
    });
    dom.tabBar.appendChild(el);
  });
}

function setActiveTab(path) {
  state.activeTab = path;
  const tab = state.openTabs.find(t => t.path === path);
  if (!tab) return;

  renderTabBar();
  dom.editorWelcome.style.display = 'none';
  dom.monacoEl.style.display = 'block';

  if (window.monacoReady) {
    window.openFileInEditor(tab.content, tab.ext, tab.name);
  } else {
    window.addEventListener('monaco-ready', () => window.openFileInEditor(tab.content, tab.ext, tab.name), { once: true });
  }
}

function closeTab(path) {
  const idx = state.openTabs.findIndex(t => t.path === path);
  if (idx === -1) return;
  state.openTabs.splice(idx, 1);

  if (state.activeTab === path) {
    state.activeTab = state.openTabs[Math.max(0, idx - 1)]?.path || null;
  }

  if (state.openTabs.length === 0) {
    dom.editorWelcome.style.display = 'flex';
    dom.monacoEl.style.display = 'none';
    dom.btnSaveFile.disabled = true;
  } else {
    setActiveTab(state.activeTab);
  }

  renderTabBar();
}

async function saveCurrentFile() {
  if (!state.activeTab || !state.projectId) return;
  const tab = state.openTabs.find(t => t.path === state.activeTab);
  if (!tab) return;

  const content = window.getEditorContent ? window.getEditorContent() : '';
  try {
    await API.writeFile(state.projectId, tab.path, content);
    tab.content = content;
    tab.modified = false;
    renderTabBar();
    toast('File saved', 'success');
    appendConsole(`[+] Saved: ${tab.path}`);
  } catch (e) {
    toast(`Save failed: ${e.message}`, 'error');
  }
}

// ─── Security Scan ────────────────────────────────────────────────────────────
async function runSecurityScan() {
  if (!state.projectId) { toast('No project open', 'warn'); return; }
  appendConsole('[*] Starting security scan...');
  toast('Scanning for security patterns...', 'info');
  try {
    await API.scan(state.projectId);
  } catch (e) {
    toast(`Scan error: ${e.message}`, 'error');
  }
}

function renderFindings(findings) {
  let total = 0;
  dom.findingsList.innerHTML = '';

  const CATEGORY_META = {
    root_detection:    { label: 'Root Detection',      color: '#ff4757' },
    license_verification: { label: 'License Verification', color: '#ffa502' },
    emulator_detection: { label: 'Emulator Detection',  color: '#2ed573' },
    ssl_pinning:        { label: 'SSL Pinning',          color: '#5352ed' },
  };

  for (const [catId, catFindings] of Object.entries(findings)) {
    if (!catFindings.length) continue;
    total += catFindings.length;

    const meta = CATEGORY_META[catId] || { label: catId, color: '#94a3b8' };

    const group = document.createElement('div');
    group.className = 'finding-group';

    const header = document.createElement('div');
    header.className = 'finding-group-label';
    header.style.cssText = `color:${meta.color};background:${meta.color}18;border-left:3px solid ${meta.color}`;
    header.textContent = `${meta.label} (${catFindings.length})`;
    group.appendChild(header);

    // Group by pattern_id
    const byPattern = {};
    catFindings.forEach(f => {
      if (!byPattern[f.pattern_id]) byPattern[f.pattern_id] = [];
      byPattern[f.pattern_id].push(f);
    });

    for (const [patId, patFindings] of Object.entries(byPattern)) {
      const first = patFindings[0];
      const item = document.createElement('div');
      item.className = 'finding-item';
      item.innerHTML = `
        <div class="finding-dot" style="background:${meta.color}"></div>
        <div class="finding-info">
          <div class="finding-label">${escHtml(first.pattern_label)}</div>
          <div class="finding-file">${escHtml(first.file)}:${first.line}</div>
        </div>
        <div class="finding-count">${patFindings.length}×</div>
      `;
      item.addEventListener('click', () => {
        openFileTab(first.file, first.file.split('/').pop(), '.' + first.file.split('.').pop());
        setTimeout(() => window.highlightLine && window.highlightLine(first.line), 300);
      });
      group.appendChild(item);
    }

    dom.findingsList.appendChild(group);
  }

  dom.findingsBadge.textContent = total;
  if (total === 0) {
    dom.findingsList.innerHTML = '<div class="findings-empty"><span style="color:var(--accent-green)">✓ No security patterns detected!</span></div>';
  }
}

// ─── Patch Engine ─────────────────────────────────────────────────────────────
async function patchAllFindings() {
  if (!state.projectId) return;

  // Collect all unique templates from findings
  const templates = new Set();
  for (const catFindings of Object.values(state.scanFindings)) {
    catFindings.forEach(f => {
      if (f.suggested_template) templates.add(f.suggested_template);
    });
  }

  if (templates.size === 0) { toast('No patchable findings', 'warn'); return; }

  appendConsole(`[*] Preview: ${templates.size} patch templates to apply...`);
  toast('Generating patch preview...', 'info');

  try {
    const result = await API.applyBatchPatch(state.projectId, [...templates], true); // dry run first
    showPatchModal('Patch All Findings Preview', `Will apply ${templates.size} templates across all matching files.`, result);
    state.pendingPatch = { batchTemplates: [...templates] };
  } catch (e) {
    toast(`Patch preview failed: ${e.message}`, 'error');
  }
}

function showPatchModal(title, desc, result) {
  dom.patchModalTitle.textContent = title;
  dom.patchModalDesc.textContent = desc;
  dom.patchDiffViewer.innerHTML = renderDiffHTML(result);
  openModal('patch');
}

async function confirmPatch() {
  closeModal('patch');
  if (!state.pendingPatch) return;
  appendConsole('[*] Applying patches...');

  try {
    let result;
    if (state.pendingPatch.batchTemplates) {
      result = await API.applyBatchPatch(state.projectId, state.pendingPatch.batchTemplates, false);
      toast(`Patched ${result.total_files} files across ${state.pendingPatch.batchTemplates.length} templates!`, 'success');
      appendConsole(`[+] Batch patch complete: ${result.total_files} files modified.`);
    } else {
      result = await API.applyPatch(state.projectId, state.pendingPatch.templateId, null, false);
      toast(`Patch applied: ${result.count} files modified`, 'success');
      appendConsole(`[+] Patch '${state.pendingPatch.templateId}': ${result.count} files.`);
    }

    // Show diff in console
    renderDiffInConsole(result);
    switchConsoleTab('diff');

    // Re-scan
    setTimeout(() => runSecurityScan(), 800);
    state.pendingPatch = null;
  } catch (e) {
    toast(`Patch failed: ${e.message}`, 'error');
    appendConsole(`[-] Patch error: ${e.message}`, 'error');
  }
}

function renderDiffHTML(result) {
  const allResults = result.results
    ? Object.values(result.results).flatMap(r => r.results || [])
    : result.results || [];

  if (!allResults.length) return '<div class="console-line console-dim">No changes to display.</div>';

  let html = '';
  const maxFiles = 10;
  const shown = allResults.slice(0, maxFiles);

  shown.forEach(r => {
    if (r.status === 'frida_generated') {
      html += `<div class="diff-file-header">📜 ${escHtml(r.file)} — Frida Hook Generated</div>`;
      html += `<pre style="color:#a78bfa;font-size:11px;padding:8px;background:rgba(124,58,237,0.08);border-radius:4px;margin:4px 0;overflow-x:auto">${escHtml(r.frida_script || '')}</pre>`;
      return;
    }
    if (!r.diff || !r.diff.length) return;
    html += `<div class="diff-file-header">📄 ${escHtml(r.file)}</div>`;
    r.diff.slice(0, 20).forEach(d => {
      const num = `<span class="diff-line-num">${d.line}</span>`;
      if (d.type === 'added') {
        html += `<div class="diff-added">+ ${num}${escHtml(d.patched || '')}</div>`;
      } else if (d.type === 'removed') {
        html += `<div class="diff-removed">- ${num}${escHtml(d.original || '')}</div>`;
      } else {
        html += `<div><span class="diff-changed-old">~ ${num}${escHtml(d.original || '')}</span></div>`;
        html += `<div><span class="diff-changed-new">+ ${num}${escHtml(d.patched || '')}</span></div>`;
      }
    });
  });

  if (allResults.length > maxFiles) {
    html += `<div class="console-line console-dim">... and ${allResults.length - maxFiles} more files</div>`;
  }

  return html;
}

function renderDiffInConsole(result) {
  dom.diffOutput.innerHTML = renderDiffHTML(result);
}

async function reviewFindingsOneByOne() {
  const allPatterns = [];
  for (const catFindings of Object.values(state.scanFindings)) {
    catFindings.forEach(f => {
      if (!allPatterns.find(p => p.suggested_template === f.suggested_template)) {
        allPatterns.push(f);
      }
    });
  }

  if (allPatterns.length === 0) { toast('No findings to review', 'warn'); return; }

  let i = 0;
  async function reviewNext() {
    if (i >= allPatterns.length) { toast('All findings reviewed!', 'success'); return; }
    const f = allPatterns[i++];
    if (!f.suggested_template) { reviewNext(); return; }

    try {
      const result = await API.applyPatch(state.projectId, f.suggested_template, null, true);
      state.pendingPatch = { templateId: f.suggested_template };
      showPatchModal(
        `Finding ${i}/${allPatterns.length}: ${f.pattern_label}`,
        `File: ${f.file}:${f.line}\nTemplate: ${f.suggested_template}`,
        result
      );
      dom.btnConfirmPatch.onclick = async () => {
        closeModal('patch');
        await API.applyPatch(state.projectId, f.suggested_template, null, false);
        toast(`Patched: ${f.suggested_template}`, 'success');
        appendConsole(`[+] Patched: ${f.suggested_template}`);
        reviewNext();
      };
    } catch(e) {
      toast(`Error: ${e.message}`, 'error');
      reviewNext();
    }
  }
  reviewNext();
}

// ─── Frida ────────────────────────────────────────────────────────────────────
async function generateFridaFromScan() {
  if (!state.projectId) return;
  appendConsole('[*] Generating Frida script from scan results...');
  try {
    const result = await API.fridaFromScan(state.projectId);
    showFridaScript(result.script);
    switchConsoleTab('frida');
    toast('Frida script generated!', 'success');
  } catch (e) {
    toast(`Frida gen failed: ${e.message}`, 'error');
  }
}

function showFridaScript(script) {
  dom.fridaOutput.innerHTML = `<pre style="color:#a78bfa;white-space:pre;line-height:1.6">${escHtml(script)}</pre>`;
}

async function generateCustomFrida() {
  if (!state.projectId) return;
  const cls = dom.fridaClass.value.trim();
  const method = dom.fridaMethod.value.trim();
  const ret = dom.fridaReturn.value;
  if (!cls || !method) { toast('Class and method required', 'warn'); return; }

  try {
    const result = await API.generateFridaHook(state.projectId, cls, method, ret);
    dom.fridaOutputModal.textContent = result.script;
  } catch (e) {
    toast(`Error: ${e.message}`, 'error');
  }
}

// ─── Build ────────────────────────────────────────────────────────────────────
async function buildAPK() {
  if (!state.projectId) { toast('No project open', 'warn'); return; }
  appendConsole('[*] Starting build pipeline...');
  toast('Building APK...', 'info');
  dom.btnBuild.disabled = true;
  try {
    await API.build(state.projectId);
  } catch (e) {
    toast(`Build error: ${e.message}`, 'error');
    dom.btnBuild.disabled = false;
  }
}

// ─── AI Chat ──────────────────────────────────────────────────────────────────
async function sendChatMessage() {
  const msg = dom.chatInput.value.trim();
  if (!msg) return;
  dom.chatInput.value = '';

  appendChatMessage('user', msg);
  addTypingIndicator();

  if (!state.projectId) {
    removeTypingIndicator();
    appendChatMessage('ai', 'Please import an APK first to enable AI analysis.');
    return;
  }

  try {
    await API.aiAnalyze(state.projectId, {
      prompt: msg,
      file: state.activeTab || null,
      ...getAISettings()
    });
  } catch (e) {
    removeTypingIndicator();
    appendChatMessage('ai', `Error: ${e.message}`);
  }
}

async function sendAIAnalyze() {
  addTypingIndicator();
  appendChatMessage('user', '🔍 Perform deep security analysis of this APK...');

  if (!state.projectId) {
    removeTypingIndicator();
    appendChatMessage('ai', 'No project open.');
    return;
  }

  try {
    await API.aiAnalyze(state.projectId, {
      file: state.activeTab || null,
      ...getAISettings()
    });
  } catch (e) {
    removeTypingIndicator();
    appendChatMessage('ai', `Error: ${e.message}`);
  }
}

function appendChatMessage(type, content) {
  const div = document.createElement('div');
  div.className = `chat-msg chat-msg-${type}`;
  const bubble = document.createElement('div');
  bubble.className = 'chat-bubble';

  if (type === 'ai') {
    bubble.textContent = content;
    // Check for action buttons in response
    if (content.includes('FINDINGS:') || content.includes('PATCH_SUGGESTIONS:')) {
      const btns = document.createElement('div');
      btns.className = 'chat-ai-btns';
      [
        ['Apply Suggested Patches', () => patchAllFindings()],
        ['Generate Frida Script', () => generateFridaFromScan()],
        ['Show Diff', () => switchConsoleTab('diff')],
      ].forEach(([label, fn]) => {
        const b = document.createElement('button');
        b.className = 'chat-ai-btn';
        b.textContent = label;
        b.addEventListener('click', fn);
        btns.appendChild(b);
      });
      bubble.appendChild(btns);
    }
  } else {
    bubble.textContent = content;
  }

  div.appendChild(bubble);
  dom.chatMessages.appendChild(div);
  dom.chatMessages.scrollTop = dom.chatMessages.scrollHeight;
}

function addTypingIndicator() {
  removeTypingIndicator();
  const div = document.createElement('div');
  div.className = 'chat-msg chat-msg-ai chat-typing';
  div.id = 'typing-indicator';
  div.innerHTML = '<div class="chat-bubble"><div class="typing-dots"><span></span><span></span><span></span></div></div>';
  dom.chatMessages.appendChild(div);
  dom.chatMessages.scrollTop = dom.chatMessages.scrollHeight;
}

function removeTypingIndicator() {
  const el = $('typing-indicator');
  if (el) el.remove();
}

// ─── AI Models ────────────────────────────────────────────────────────────────
async function fetchModels() {
  const provider = dom.aiProvider.value;
  const url = dom.aiUrl.value.trim();
  const dot = dom.chipAI.querySelector('.status-dot');
  dot.className = 'status-dot dot-checking';

  try {
    const { models } = await API.getModels(provider, url);
    dom.aiModel.innerHTML = '';
    (models.length ? models : ['(no models found)']).forEach(m => {
      const opt = document.createElement('option');
      opt.value = m; opt.textContent = m;
      dom.aiModel.appendChild(opt);
    });
    dot.className = 'status-dot ' + (models.length ? 'dot-ok' : 'dot-warn');
  } catch(e) {
    dot.className = 'status-dot dot-err';
    toast(`Cannot connect to ${provider}: ${e.message}`, 'warn');
  }
}

function getAISettings() {
  return {
    ai_provider: dom.aiProvider.value,
    ai_model: dom.aiModel.value,
    api_key: dom.aiKey.value,
    custom_url: dom.aiUrl.value,
  };
}

// ─── Manifest Info ────────────────────────────────────────────────────────────
function updateManifestInfo(manifest) {
  dom.infoPkg.textContent = manifest.package || '—';
  dom.infoVer.textContent = manifest.version || '—';
  dom.infoSdk.textContent = manifest.target_sdk || '—';
  if (manifest.debuggable) dom.infoDebuggable.style.display = 'flex';
  if (manifest.cleartext_traffic) dom.infoCleartext.style.display = 'flex';
}

// ─── Console ──────────────────────────────────────────────────────────────────
function appendConsole(message, type = 'info') {
  const line = document.createElement('div');
  line.className = `console-line console-${classForLog(message, type)}`;
  line.textContent = message;
  dom.consoleOutput.appendChild(line);
  dom.consoleOutput.scrollTop = dom.consoleOutput.scrollHeight;
}

function appendConsoleHTML(html, type = 'info') {
  const line = document.createElement('div');
  line.className = `console-line console-${type}`;
  line.innerHTML = html;
  dom.consoleOutput.appendChild(line);
  dom.consoleOutput.scrollTop = dom.consoleOutput.scrollHeight;
}

function classForLog(msg, fallback = 'info') {
  if (msg.startsWith('[+]')) return 'success';
  if (msg.startsWith('[-]')) return 'error';
  if (msg.startsWith('[!]')) return 'warn';
  if (msg.startsWith('[*]')) return 'highlight';
  return fallback;
}

function switchConsoleTab(tab) {
  document.querySelectorAll('.console-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  document.querySelectorAll('.console-pane').forEach(p => p.classList.toggle('active', p.id === `pane-${tab}`));
}

function toggleConsole() {
  state.consoleCollapsed = !state.consoleCollapsed;
  dom.consoleStrip.classList.toggle('collapsed', state.consoleCollapsed);
  const icon = dom.btnToggleConsole.querySelector('svg polyline');
  if (icon) icon.setAttribute('points', state.consoleCollapsed ? '6 9 12 15 18 9' : '18 15 12 9 6 15');
}

// ─── Context Menu ─────────────────────────────────────────────────────────────
let ctxPosition = null;
function showContextMenu({ x, y, position, lineContent }) {
  ctxPosition = position;
  dom.contextMenu.style.left = `${x}px`;
  dom.contextMenu.style.top = `${y}px`;
  dom.contextMenu.classList.remove('hidden');

  // Adjust if off-screen
  const rect = dom.contextMenu.getBoundingClientRect();
  if (rect.right > window.innerWidth) dom.contextMenu.style.left = `${x - rect.width}px`;
  if (rect.bottom > window.innerHeight) dom.contextMenu.style.top = `${y - rect.height}px`;
}

function hideContextMenu() {
  dom.contextMenu.classList.add('hidden');
}

async function handleContextAction(action) {
  hideContextMenu();
  if (!state.activeTab) return;

  const lineNum = ctxPosition?.lineNumber || 1;
  const model = window.monacoEditor?.getModel();
  const lineContent = model?.getLineContent(lineNum) || '';

  switch (action) {
    case 'patch-true': {
      // NOP - replace line with return true smali
      toast('Select a method to patch in the findings panel', 'info');
      break;
    }
    case 'patch-false': {
      toast('Select a method to patch in the findings panel', 'info');
      break;
    }
    case 'nop-block': {
      if (model && lineNum) {
        const content = model.getValue();
        const lines = content.split('\n');
        lines[lineNum - 1] = '    nop  # [APK Studio] NOPed';
        model.setValue(lines.join('\n'));
        toast(`Replaced line ${lineNum} with NOP`, 'success');
      }
      break;
    }
    case 'gen-frida': {
      // Extract class/method from smali line
      const classMatch = lineContent.match(/L([^;]+);->(\w+)/);
      if (classMatch) {
        dom.fridaClass.value = classMatch[1].replace(/\//g, '.');
        dom.fridaMethod.value = classMatch[2];
      }
      openModal('frida');
      break;
    }
    case 'add-log': {
      if (model && lineNum) {
        const lines = model.getValue().split('\n');
        lines.splice(lineNum - 1, 0, `    const-string v0, "[APK Studio LOG] Line ${lineNum}"\n    invoke-static {v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I`);
        model.setValue(lines.join('\n'));
        toast('Log statement added', 'success');
      }
      break;
    }
    case 'ask-ai': {
      dom.chatInput.value = `Explain this smali line: ${lineContent.trim()}`;
      sendChatMessage();
      break;
    }
  }
}

// ─── Modals ───────────────────────────────────────────────────────────────────
function openModal(name) {
  $(`modal-${name}`).classList.remove('hidden');
}
function closeModal(name) {
  $(`modal-${name}`).classList.add('hidden');
}

// ─── Settings ─────────────────────────────────────────────────────────────────
function saveSettings() {
  state.settings.ai_provider = dom.settingsProvider.value;
  state.settings.ai_model = dom.settingsModel.value;
  state.settings.api_key = dom.settingsKey.value;
  state.settings.auto_sign = dom.optAutoSign.checked;
  state.settings.auto_scan = dom.optAutoScan.checked;

  // Sync to AI panel
  dom.aiProvider.value = state.settings.ai_provider;
  dom.aiKey.value = state.settings.api_key;

  localStorage.setItem('apkstudio_settings', JSON.stringify(state.settings));
  closeModal('settings');
  toast('Settings saved', 'success');
  fetchModels();
}

function loadSettings() {
  try {
    const saved = JSON.parse(localStorage.getItem('apkstudio_settings') || '{}');
    Object.assign(state.settings, saved);
    dom.settingsProvider.value = state.settings.ai_provider;
    dom.settingsModel.value = state.settings.ai_model;
    dom.settingsKey.value = state.settings.api_key;
    dom.aiProvider.value = state.settings.ai_provider;
    dom.aiModel.value = state.settings.ai_model;
    dom.aiKey.value = state.settings.api_key;
    dom.optAutoSign.checked = state.settings.auto_sign;
    dom.optAutoScan.checked = state.settings.auto_scan;
  } catch(e) {}
}

// ─── Resize Handles ───────────────────────────────────────────────────────────
function initResizeHandles() {
  setupResizeHandle('resize-left', 'panel-left', 'left');
  setupResizeHandle('resize-right', 'panel-right', 'right');
}

function setupResizeHandle(handleId, panelId, side) {
  const handle = $(handleId);
  const panel = document.querySelector(`.${panelId}`);
  if (!handle || !panel) return;

  let startX, startW;
  handle.addEventListener('mousedown', (e) => {
    startX = e.clientX;
    startW = panel.offsetWidth;
    handle.classList.add('dragging');
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  });

  function onMove(e) {
    const dx = e.clientX - startX;
    let newW = side === 'left' ? startW + dx : startW - dx;
    newW = Math.max(180, Math.min(600, newW));
    panel.style.width = newW + 'px';
  }

  function onUp() {
    handle.classList.remove('dragging');
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  }
}

// ─── Keyboard Shortcuts ───────────────────────────────────────────────────────
function initKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey) {
      switch (e.key) {
        case 'o': case 'O': e.preventDefault(); dom.fileInput.click(); break;
        case 's': case 'S': e.preventDefault(); saveCurrentFile(); break;
      }
    }
    if (e.key === 'F5') { e.preventDefault(); runSecurityScan(); }
    if (e.key === 'F6') { e.preventDefault(); buildAPK(); }
    if (e.key === 'Escape') { hideContextMenu(); }
  });
}

// ─── Toolbar Button State ─────────────────────────────────────────────────────
function enableToolbarButtons() {
  dom.btnBuild.disabled = false;
  dom.btnScan.disabled = false;
}

// ─── Breadcrumb ───────────────────────────────────────────────────────────────
function updateBreadcrumb(name, id) {
  dom.breadcrumb.innerHTML = `
    <span class="breadcrumb-item">${escHtml(name)}</span>
    <span class="breadcrumb-item dim">ID: ${id}</span>
  `;
}

// ─── Toast Notifications ──────────────────────────────────────────────────────
function toast(message, type = 'info', duration = 3500) {
  const icons = {
    success: '✅', error: '❌', warn: '⚠️', info: 'ℹ️'
  };
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.innerHTML = `<span>${icons[type] || ''}</span><span>${escHtml(message)}</span>`;
  dom.toastContainer.appendChild(el);
  setTimeout(() => {
    el.classList.add('out');
    setTimeout(() => el.remove(), 300);
  }, duration);
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => toast('Copied to clipboard!', 'success'));
}

// ─── Styles for download link ─────────────────────────────────────────────────
const dlStyle = document.createElement('style');
dlStyle.textContent = `.dl-link{color:var(--accent-cyan);text-decoration:underline;cursor:pointer}`;
document.head.appendChild(dlStyle);

// ─── Bootstrap ────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);
