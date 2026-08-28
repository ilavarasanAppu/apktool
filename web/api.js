/**
 * APK Security Studio — API Client
 * Fetch wrappers for all backend endpoints with error handling.
 */

const API_BASE = '';  // Same origin

class APIError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function apiFetch(path, options = {}) {
  try {
    const res = await fetch(API_BASE + path, {
      headers: { 'Content-Type': 'application/json', ...options.headers },
      ...options
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new APIError(body.error || `HTTP ${res.status}`, res.status);
    }
    return await res.json();
  } catch (e) {
    if (e instanceof APIError) throw e;
    throw new APIError(e.message || 'Network error', 0);
  }
}

// ─── Health ──────────────────────────────────────────────────────────────────
window.API = {

  health: () => apiFetch('/api/health'),

  // ─── Projects ──────────────────────────────────────────────────────────────
  listProjects: () => apiFetch('/api/projects'),
  deleteProject: (id) => apiFetch(`/api/projects/${id}`, { method: 'DELETE' }),

  // ─── Upload ────────────────────────────────────────────────────────────────
  uploadAPK: async (file, settings = {}, onProgress = null) => {
    const form = new FormData();
    form.append('apk', file);
    form.append('ai_provider', settings.ai_provider || 'ollama');
    form.append('ai_model', settings.ai_model || 'mistral');
    form.append('api_key', settings.api_key || '');
    form.append('custom_url', settings.custom_url || '');

    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/upload');

      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable && onProgress) {
          onProgress(Math.round((e.loaded / e.total) * 100));
        }
      };

      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(JSON.parse(xhr.responseText));
        } else {
          const body = JSON.parse(xhr.responseText || '{}');
          reject(new APIError(body.error || 'Upload failed', xhr.status));
        }
      };

      xhr.onerror = () => reject(new APIError('Network error', 0));
      xhr.send(form);
    });
  },

  // ─── Decode ────────────────────────────────────────────────────────────────
  decode: (projectId) =>
    apiFetch(`/api/${projectId}/decode`, { method: 'POST' }),

  // ─── File Tree ─────────────────────────────────────────────────────────────
  getTree: (projectId) => apiFetch(`/api/${projectId}/tree`),

  // ─── File Operations ───────────────────────────────────────────────────────
  readFile: (projectId, path) =>
    apiFetch(`/api/${projectId}/file?path=${encodeURIComponent(path)}`),

  writeFile: (projectId, path, content) =>
    apiFetch(`/api/${projectId}/file`, {
      method: 'PUT',
      body: JSON.stringify({ path, content })
    }),

  revertFile: (projectId, path) =>
    apiFetch(`/api/${projectId}/file/revert`, {
      method: 'POST',
      body: JSON.stringify({ path })
    }),

  // ─── Security Scan ─────────────────────────────────────────────────────────
  scan: (projectId) =>
    apiFetch(`/api/${projectId}/scan`, { method: 'POST' }),

  getScanResults: (projectId) =>
    apiFetch(`/api/${projectId}/scan/results`),

  // ─── Patch Templates ───────────────────────────────────────────────────────
  getTemplates: () => apiFetch('/api/patch-templates'),

  applyPatch: (projectId, templateId, targetFile = null, dryRun = false) =>
    apiFetch(`/api/${projectId}/patch`, {
      method: 'POST',
      body: JSON.stringify({ template_id: templateId, target_file: targetFile, dry_run: dryRun })
    }),

  applyBatchPatch: (projectId, templateIds, dryRun = false) =>
    apiFetch(`/api/${projectId}/patch/batch`, {
      method: 'POST',
      body: JSON.stringify({ template_ids: templateIds, dry_run: dryRun })
    }),

  getPatchHistory: (projectId) =>
    apiFetch(`/api/${projectId}/patch/history`),

  // ─── Frida ─────────────────────────────────────────────────────────────────
  generateFridaHook: (projectId, className, methodName, returnValue = 'false') =>
    apiFetch(`/api/${projectId}/frida/hook`, {
      method: 'POST',
      body: JSON.stringify({ class_name: className, method_name: methodName, return_value: returnValue })
    }),

  fridaFromScan: (projectId) =>
    apiFetch(`/api/${projectId}/frida/from-scan`, { method: 'POST' }),

  // ─── Build ─────────────────────────────────────────────────────────────────
  build: (projectId) =>
    apiFetch(`/api/${projectId}/build`, { method: 'POST' }),

  downloadURL: (projectId, filename) =>
    `/api/${projectId}/download/${encodeURIComponent(filename)}`,

  // ─── AI ────────────────────────────────────────────────────────────────────
  aiAnalyze: (projectId, settings = {}) =>
    apiFetch(`/api/${projectId}/ai/analyze`, {
      method: 'POST',
      body: JSON.stringify(settings)
    }),

  getModels: (provider, url = '') =>
    apiFetch(`/api/ai/models?provider=${provider}&url=${encodeURIComponent(url)}`),

  // ─── Manifest / Analysis ───────────────────────────────────────────────────
  getManifest: (projectId) => apiFetch(`/api/${projectId}/manifest`),
  getAnalysis: (projectId) => apiFetch(`/api/${projectId}/analysis`),
};
