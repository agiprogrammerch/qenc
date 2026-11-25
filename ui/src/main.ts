import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { open, save } from '@tauri-apps/plugin-dialog';
import { getCurrentWebview } from '@tauri-apps/api/webview';
import type {
  QencMetadata,
  ProgressEvent,
  InspectResponse,
  EncryptRequest,
  DecryptRequest,
  OperationSummary,
  KeygenRequest,
  KeygenSummary,
  SystemInfo,
  Toast,
  FileItem,
  InputPathInfo,
  DefaultPaths,
} from './types';

// --- State ---
interface AppState {
  encrypt: {
    files: FileItem[];
    mode: 'passphrase' | 'hybridPqc';
    profile: 'turbo' | 'balanced' | 'ultra';
    passphrase: string;
    passphraseConfirm: string;
    pubkeyPath: string;
    outputPath: string;
  };
  decrypt: {
    inputPath: string;
    metadata: QencMetadata | null;
    mode: 'passphrase' | 'hybridPqc' | null;
    passphrase: string;
    secKeyPath: string;
    secKeyPassphrase: string;
    outputPath: string;
  };
  keys: {
    namePrefix: string;
    outputDir: string;
    passphrase: string;
  };
  activeOperation: boolean;
  progressThrottle: number;
  isMobile: boolean;
  argonRecommendation: 'desktop' | 'mobile';
}

const state: AppState = {
  encrypt: {
    files: [],
    mode: 'passphrase',
    profile: 'balanced',
    passphrase: '',
    passphraseConfirm: '',
    pubkeyPath: '',
    outputPath: '',
  },
  decrypt: {
    inputPath: '',
    metadata: null,
    mode: null,
    passphrase: '',
    secKeyPath: '',
    secKeyPassphrase: '',
    outputPath: '',
  },
  keys: {
    namePrefix: 'qenc-key',
    outputDir: '',
    passphrase: '',
  },
  activeOperation: false,
  progressThrottle: 0,
  isMobile: false,
  argonRecommendation: 'desktop',
};

// --- DOM Elements ---
const els = {
  // Tabs
  tabs: document.querySelectorAll('.tab'),
  panels: document.querySelectorAll('.tab-panel'),

  // Encrypt
  encryptDropZone: document.getElementById('encryptDropZone') as HTMLElement,
  encryptFileList: document.getElementById('encryptFileList') as HTMLElement,
  profileRadios: document.querySelectorAll('input[name="profile"]') as NodeListOf<HTMLInputElement>,
  modeRadios: document.querySelectorAll('input[name="mode"]') as NodeListOf<HTMLInputElement>,
  passphraseFields: document.getElementById('passphraseFields') as HTMLElement,
  hybridFields: document.getElementById('hybridFields') as HTMLElement,
  passphraseInput: document.getElementById('passphraseInput') as HTMLInputElement,
  passphraseConfirm: document.getElementById('passphraseConfirm') as HTMLInputElement,
  passphraseStrength: document.getElementById('passphraseStrength') as HTMLElement,
  strengthText: document.getElementById('strengthText') as HTMLElement,
  matchIndicator: document.getElementById('matchIndicator') as HTMLElement,
  pubkeyInput: document.getElementById('pubkeyInput') as HTMLInputElement,
  pubkeySelected: document.getElementById('pubkeySelected') as HTMLElement,
  browsePubkey: document.getElementById('browsePubkey') as HTMLButtonElement,
  encryptOutput: document.getElementById('encryptOutput') as HTMLInputElement,
  browseEncryptOutput: document.getElementById('browseEncryptOutput') as HTMLButtonElement,
  btnEncrypt: document.getElementById('btnEncrypt') as HTMLButtonElement,
  encryptInputSize: document.getElementById('encryptInputSize') as HTMLElement,

  // Decrypt
  decryptDropZone: document.getElementById('decryptDropZone') as HTMLElement,
  metadataCard: document.getElementById('metadataCard') as HTMLElement,
  metadataGrid: document.getElementById('metadataGrid') as HTMLElement,
  metaMode: document.getElementById('metaMode') as HTMLElement,
  metaCompression: document.getElementById('metaCompression') as HTMLElement,
  metaArchiveSize: document.getElementById('metaArchiveSize') as HTMLElement,
  metaOriginalSize: document.getElementById('metaOriginalSize') as HTMLElement,
  metaRatio: document.getElementById('metaRatio') as HTMLElement,
  argon2Row: document.getElementById('argon2Row') as HTMLElement,
  metaArgon2: document.getElementById('metaArgon2') as HTMLElement,
  decryptFields: document.getElementById('decryptFields') as HTMLElement,
  decryptPassphraseFields: document.getElementById('decryptPassphraseFields') as HTMLElement,
  decryptHybridFields: document.getElementById('decryptHybridFields') as HTMLElement,
  decryptPassphrase: document.getElementById('decryptPassphrase') as HTMLInputElement,
  decryptSecKey: document.getElementById('decryptSecKey') as HTMLInputElement,
  decryptSecKeySelected: document.getElementById('decryptSecKeySelected') as HTMLElement,
  browseDecryptSecKey: document.getElementById('browseDecryptSecKey') as HTMLButtonElement,
  decryptSecPassphrase: document.getElementById('decryptSecPassphrase') as HTMLInputElement,
  decryptOutput: document.getElementById('decryptOutput') as HTMLInputElement,
  browseDecryptOutput: document.getElementById('browseDecryptOutput') as HTMLButtonElement,
  btnDecrypt: document.getElementById('btnDecrypt') as HTMLButtonElement,
  decryptFileName: document.getElementById('decryptFileName') as HTMLElement,

  // Keys
  keyName: document.getElementById('keyName') as HTMLInputElement,
  keyOutput: document.getElementById('keyOutput') as HTMLInputElement,
  browseKeyOutput: document.getElementById('browseKeyOutput') as HTMLButtonElement,
  keyPassphrase: document.getElementById('keyPassphrase') as HTMLInputElement,
  btnGenerateKey: document.getElementById('btnGenerateKey') as HTMLButtonElement,
  keyResultCard: document.getElementById('keyResultCard') as HTMLElement,
  keyResultGrid: document.getElementById('keyResultGrid') as HTMLElement,

  // Progress
  progressOverlay: document.getElementById('progressOverlay') as HTMLElement,
  progressTitle: document.getElementById('progressTitle') as HTMLElement,
  progressStage: document.getElementById('progressStage') as HTMLElement,
  progressBar: document.getElementById('progressBar') as HTMLElement,
  progressPercent: document.getElementById('progressPercent') as HTMLElement,
  progressThroughput: document.getElementById('progressThroughput') as HTMLElement,
  progressProcessed: document.getElementById('progressProcessed') as HTMLElement,
  progressElapsed: document.getElementById('progressElapsed') as HTMLElement,
  progressDetail: document.getElementById('progressDetail') as HTMLElement,
  btnCancel: document.getElementById('btnCancel') as HTMLButtonElement,

  // Toast
  toastContainer: document.getElementById('toastContainer') as HTMLElement,
};

// --- Utility Functions ---
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(ms: number): string {
  const sec = Math.floor(ms / 1000);
  const min = Math.floor(sec / 60);
  const hour = Math.floor(min / 60);
  if (hour > 0) return `${hour}:${String(min % 60).padStart(2, '0')}:${String(sec % 60).padStart(2, '0')}`;
  if (min > 0) return `${min}:${String(sec % 60).padStart(2, '0')}`;
  return `${sec}s`;
}

function calculatePassphraseStrength(passphrase: string): { score: number; label: string; color: string } {
  if (!passphrase) return { score: 0, label: 'Enter a passphrase', color: 'var(--muted)' };

  let score = 0;
  if (passphrase.length >= 8) score += 20;
  if (passphrase.length >= 12) score += 15;
  if (passphrase.length >= 20) score += 15;
  if (/[a-z]/.test(passphrase)) score += 10;
  if (/[A-Z]/.test(passphrase)) score += 10;
  if (/[0-9]/.test(passphrase)) score += 10;
  if (/[^a-zA-Z0-9]/.test(passphrase)) score += 15;
  if (/(.)\1{2,}/.test(passphrase)) score -= 10; // repeated chars
  score = Math.max(0, Math.min(100, score));

  if (score < 30) return { score, label: 'Weak', color: 'var(--danger)' };
  if (score < 60) return { score, label: 'Fair', color: 'var(--warning)' };
  if (score < 80) return { score, label: 'Good', color: 'var(--accent)' };
  return { score, label: 'Strong', color: 'var(--success)' };
}

function checkPassphraseMatch(): void {
  const match = els.passphraseInput.value === els.passphraseConfirm.value && els.passphraseInput.value.length > 0;
  els.matchIndicator.textContent = match ? '✓ Passphrases match' : '✗ Passphrases do not match';
  els.matchIndicator.style.color = match ? 'var(--success)' : 'var(--danger)';
}

function showToast(toast: Omit<Toast, 'id'>): void {
  const id = Math.random().toString(36).slice(2, 9);
  const el = document.createElement('div');
  el.className = `toast toast-${toast.type}`;
  el.dataset.id = id;
  el.innerHTML = `
    <div class="toast-icon">
      ${toast.type === 'success' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' : ''}
      ${toast.type === 'error' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>' : ''}
      ${toast.type === 'warning' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' : ''}
      ${toast.type === 'info' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>' : ''}
    </div>
    <div class="toast-content">
      <div class="toast-title">${toast.title}</div>
      ${toast.message ? `<div class="toast-message">${toast.message}</div>` : ''}
    </div>
    <button class="toast-close" aria-label="Dismiss"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
  `;

  el.querySelector('.toast-close')!.addEventListener('click', () => el.remove());
  els.toastContainer.appendChild(el);

  // Animate in
  requestAnimationFrame(() => el.classList.add('show'));

  const duration = toast.duration ?? (toast.type === 'error' ? 8000 : 5000);
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 200);
  }, duration);
}

// --- Tab Navigation ---
function switchTab(tabName: string): void {
  els.tabs.forEach((tab) => {
    const el = tab as HTMLElement;
    const isActive = el.dataset.tab === tabName;
    el.setAttribute('aria-selected', isActive.toString());
    el.classList.toggle('active', isActive);
  });
  els.panels.forEach((panel) => {
    const el = panel as HTMLElement;
    const isActive = el.dataset.tab === tabName;
    el.classList.toggle('hidden', !isActive);
    el.setAttribute('aria-hidden', (!isActive).toString());
  });
}

els.tabs.forEach((tab) => {
  tab.addEventListener('click', () => switchTab((tab as HTMLElement).dataset.tab!));
});

// --- File Picker Helpers ---
async function pickFiles(
  options: { multiple?: boolean; directory?: boolean; filters?: { name: string; extensions: string[] }[] } = {}
): Promise<string[]> {
  try {
    const result = await open({
      multiple: options.multiple ?? false,
      directory: options.directory ?? false,
      filters: options.filters,
    });
    if (!result) return [];
    return Array.isArray(result) ? result : [result];
  } catch (err) {
    console.error('File picker error:', err);
    showToast({ type: 'error', title: 'File Selection Failed', message: String(err) });
    return [];
  }
}

async function pickSaveFile(
  inputEl: HTMLInputElement,
  filters: { name: string; extensions: string[] }[],
  defaultName: string
): Promise<void> {
  try {
    const path = await save({
      filters,
      defaultPath: defaultName,
    });
    if (path) {
      inputEl.value = path;
    }
  } catch (err) {
    console.error('Save file error:', err);
    showToast({ type: 'error', title: 'Save Failed', message: String(err) });
  }
}

function updateFileInputDisplay(inputEl: HTMLInputElement, selectedEl: HTMLElement, path: string): void {
  inputEl.value = path;
  selectedEl.textContent = path.split(/[/\\]/).pop() || path;
  selectedEl.classList.remove('hidden');
}

// Helper functions for file pickers
async function pickFile(
  inputEl: HTMLInputElement,
  selectedEl: HTMLElement,
  filters: { name: string; extensions: string[] }[]
): Promise<void> {
  const paths = await pickFiles({ multiple: false, filters });
  if (paths.length > 0) {
    updateFileInputDisplay(inputEl, selectedEl, paths[0]);
  }
}

async function pickDirectory(inputEl: HTMLInputElement): Promise<void> {
  const paths = await pickFiles({ directory: true, multiple: false });
  if (paths.length > 0) {
    inputEl.value = paths[0];
  }
}

// --- Encrypt File List ---
function renderEncryptFileList(): void {
  els.encryptFileList.innerHTML = '';
  if (state.encrypt.files.length === 0) {
    els.encryptInputSize.textContent = 'No files selected';
    els.btnEncrypt.disabled = true;
    return;
  }

  const totalSize = state.encrypt.files.reduce((sum, f) => sum + f.size, 0);
  els.encryptInputSize.textContent = `${state.encrypt.files.length} item(s), ${formatBytes(totalSize)}`;
  els.btnEncrypt.disabled = false;

  state.encrypt.files.forEach((file, index) => {
    const item = document.createElement('div');
    item.className = 'file-item';
    item.innerHTML = `
      <svg class="file-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
        ${file.isDirectory
          ? '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>'
          : '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>'}
      </svg>
      <div class="file-info">
        <span class="file-name">${file.name}</span>
        <span class="file-size">${formatBytes(file.size)}${file.isDirectory ? ' (folder)' : ''}</span>
      </div>
      <button class="file-remove" aria-label="Remove ${file.name}" data-index="${index}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    `;
    els.encryptFileList.appendChild(item);
  });

  els.encryptFileList.querySelectorAll('.file-remove').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const index = parseInt((e.currentTarget as HTMLElement).dataset.index!, 10);
      state.encrypt.files.splice(index, 1);
      renderEncryptFileList();
    });
  });
}

async function addFilesToEncrypt(paths: string[]): Promise<void> {
  if (paths.length === 0) return;

  // Get file info from Rust backend
  try {
    const response = await invoke<InputPathInfo[]>('inspect_input_paths', { paths });
    for (const info of response) {
      // Check if already added
      if (state.encrypt.files.some((f) => f.path === info.path)) continue;
      state.encrypt.files.push({
        path: info.path,
        name: info.name,
        size: info.sizeBytes ?? 0,
        isDirectory: info.isDir ?? false,
      });
    }
    renderEncryptFileList();
  } catch (err) {
    console.error('Failed to inspect input paths:', err);
    showToast({ type: 'error', title: 'Failed to add files', message: String(err) });
  }
}

// --- Decrypt File Handling ---
async function loadDecryptFile(path: string): Promise<void> {
  state.decrypt.inputPath = path;
  els.decryptFileName.textContent = path.split(/[/\\]/).pop() || path;
  els.decryptFileName.classList.remove('hidden');
  els.btnDecrypt.disabled = true;
  els.metadataCard.classList.add('hidden');
  els.decryptFields.classList.add('hidden');

  try {
    const response = await invoke<InspectResponse>('inspect_container', { path });
    state.decrypt.metadata = response.metadata;
    renderMetadata(response.metadata);
    els.metadataCard.classList.remove('hidden');
    els.decryptFields.classList.remove('hidden');
    updateDecryptCredentialsUI(response.metadata.keyMode);
    els.btnDecrypt.disabled = false;
  } catch (err) {
    showToast({ type: 'error', title: 'Inspection Failed', message: String(err) });
  }
}

function renderMetadata(meta: QencMetadata): void {
  els.metaMode.textContent = meta.keyMode === 'passphrase' ? 'Argon2id (Passphrase)' : 'Hybrid X25519 + ML-KEM-1024';
  els.metaCompression.textContent = meta.compressionProfile ?? '—';
  els.metaArchiveSize.textContent = formatBytes(meta.originalSize ?? 0);
  els.metaOriginalSize.textContent = formatBytes(meta.originalSize ?? 0);
  els.metaRatio.textContent = '—';

  if (meta.keyMode === 'passphrase' && meta.argon2Params) {
    const { mCostKib, tCost, pCost } = meta.argon2Params;
    els.metaArgon2.textContent = `${mCostKib} KiB memory, ${tCost} iterations, ${pCost} parallelism`;
    els.argon2Row.classList.remove('hidden');
  } else {
    els.argon2Row.classList.add('hidden');
  }
}

function updateDecryptCredentialsUI(mode: 'passphrase' | 'hybridPqc'): void {
  state.decrypt.mode = mode;
  els.decryptPassphraseFields.classList.toggle('hidden', mode !== 'passphrase');
  els.decryptHybridFields.classList.toggle('hidden', mode !== 'hybridPqc');
}

// --- Drag and Drop (Tauri v2) ---
function setupTauriDragAndDrop(): void {
  const webview = getCurrentWebview();
  
  webview.onDragDropEvent((event) => {
    const payload = event.payload;
    const activeTab = (document.querySelector('.tab.active') as HTMLElement | null)?.dataset.tab;
    
    // Handle drag enter/over - highlight drop zone
    if (payload.type === 'enter' || payload.type === 'over') {
      if (activeTab === 'encrypt') {
        els.encryptDropZone.classList.add('drag-active');
      } else if (activeTab === 'decrypt') {
        els.decryptDropZone.classList.add('drag-active');
      }
      return;
    }
    
    // Handle drag leave
    if (payload.type === 'leave') {
      els.encryptDropZone.classList.remove('drag-active');
      els.decryptDropZone.classList.remove('drag-active');
      return;
    }
    
    // Handle drop - payload has paths property
    if (payload.type === 'drop' && payload.paths) {
      const paths = payload.paths;
      els.encryptDropZone.classList.remove('drag-active');
      els.decryptDropZone.classList.remove('drag-active');
      
      if (activeTab === 'encrypt') {
        // On Encrypt tab: add all dropped files/folders
        addFilesToEncrypt(paths);
      } else if (activeTab === 'decrypt') {
        // On Decrypt tab: handle intelligently
        const qencFiles = paths.filter(p => p.toLowerCase().endsWith('.qenc'));
        const secFiles = paths.filter(p => p.toLowerCase().endsWith('.qenc.sec'));
        
        if (qencFiles.length > 0) {
          // Prioritize .qenc file
          loadDecryptFile(qencFiles[0]);
          if (secFiles.length > 0) {
            // Also populate secret key if dropped
            updateFileInputDisplay(els.decryptSecKey, els.decryptSecKeySelected, secFiles[0]);
          }
        } else if (secFiles.length > 0) {
          // Only .qenc.sec dropped
          updateFileInputDisplay(els.decryptSecKey, els.decryptSecKeySelected, secFiles[0]);
          showToast({ type: 'info', title: 'Secret Key Selected', message: 'Please also drop or select a .qenc file to decrypt' });
        } else {
          showToast({ type: 'error', title: 'Invalid File', message: 'Please drop a .qenc file (and optionally a .qenc.sec file)' });
        }
      }
    }
  });

  // Prevent default browser navigation on window dragover/drop
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => e.preventDefault());
}

// --- Drop Zone Click Handlers ---
function setupDropZoneClickHandlers(): void {
  // Encrypt drop zone - click to add files or folder
  els.encryptDropZone.addEventListener('click', async () => {
    const paths = await pickFiles({ multiple: true });
    if (paths.length > 0) {
      await addFilesToEncrypt(paths);
    }
  });

  // Decrypt drop zone - click to select .qenc file
  els.decryptDropZone.addEventListener('click', async () => {
    const paths = await pickFiles({ 
      multiple: false, 
      filters: [{ name: 'QENC Container', extensions: ['qenc'] }] 
    });
    if (paths.length > 0) {
      await loadDecryptFile(paths[0]);
    }
  });
}

// --- Encrypt Action ---
els.btnEncrypt.addEventListener('click', async () => {
  if (state.encrypt.files.length === 0) return;
  if (!els.encryptOutput.value) {
    showToast({ type: 'error', title: 'Missing Output', message: 'Please choose an output location' });
    return;
  }

  if (state.encrypt.mode === 'passphrase') {
    const passphrase = els.passphraseInput.value;
    const confirm = els.passphraseConfirm.value;
    if (!passphrase) {
      showToast({ type: 'error', title: 'Missing Passphrase', message: 'Please enter a passphrase' });
      return;
    }
    if (passphrase !== confirm) {
      showToast({ type: 'error', title: 'Passphrase Mismatch', message: 'Passphrases do not match' });
      return;
    }
    state.encrypt.passphrase = passphrase;
  } else {
    if (!els.pubkeyInput.value) {
      showToast({ type: 'error', title: 'Missing Public Key', message: 'Please select a recipient .qenc.pub file' });
      return;
    }
    state.encrypt.pubkeyPath = els.pubkeyInput.value;
  }

  state.encrypt.outputPath = els.encryptOutput.value;
  await runEncrypt();
});

async function runEncrypt(): Promise<void> {
  setActiveOperation(true);
  await showProgress('Encrypting…', 'Archiving…');

  try {
    const request: EncryptRequest = {
      inputs: state.encrypt.files.map((f) => f.path),
      output: state.encrypt.outputPath,
      mode: state.encrypt.mode,
      profile: state.encrypt.profile,
    };

    if (state.encrypt.mode === 'passphrase') {
      request.passphrase = state.encrypt.passphrase;
    } else {
      request.recipientPubkeyPath = state.encrypt.pubkeyPath;
    }

    const summary = await invoke<OperationSummary>('encrypt_files', { req: request });
    hideProgress();
    showToast({
      type: 'success',
      title: 'Encryption Complete',
      message: `Output: ${formatBytes(summary.outputSize ?? 0)} (${(summary.compressionRatioPercent ?? 0).toFixed(1)}% ratio) in ${formatDuration(summary.elapsedMs ?? 0)}`,
    });
    // Reset form
    state.encrypt.files = [];
    renderEncryptFileList();
    els.encryptOutput.value = '';
    els.passphraseInput.value = '';
    els.passphraseConfirm.value = '';
    els.pubkeyInput.value = '';
    els.pubkeySelected.textContent = '';
    els.pubkeySelected.classList.add('hidden');
    const strengthFill = els.passphraseStrength.querySelector('.strength-fill') as HTMLElement;
    strengthFill.style.width = '0%';
    els.strengthText.textContent = 'Enter a passphrase';
    els.matchIndicator.textContent = '';
  } catch (err) {
    hideProgress();
    const msg = String(err);
    if (msg.includes('Cancelled')) {
      showToast({ type: 'warning', title: 'Cancelled', message: 'Encryption was cancelled' });
    } else {
      showToast({ type: 'error', title: 'Encryption Failed', message: msg });
    }
  } finally {
    setActiveOperation(false);
  }
}

// --- Decrypt Action ---
els.btnDecrypt.addEventListener('click', async () => {
  if (!state.decrypt.inputPath) return;
  if (!els.decryptOutput.value) {
    showToast({ type: 'error', title: 'Missing Output', message: 'Please choose an output directory' });
    return;
  }

  if (state.decrypt.mode === 'passphrase') {
    const passphrase = els.decryptPassphrase.value;
    if (!passphrase) {
      showToast({ type: 'error', title: 'Missing Passphrase', message: 'Please enter the passphrase' });
      return;
    }
    state.decrypt.passphrase = passphrase;
  } else {
    if (!els.decryptSecKey.value) {
      showToast({ type: 'error', title: 'Missing Secret Key', message: 'Please select the .qenc.sec file' });
      return;
    }
    state.decrypt.secKeyPath = els.decryptSecKey.value;
    state.decrypt.secKeyPassphrase = els.decryptSecPassphrase.value;
  }

  state.decrypt.outputPath = els.decryptOutput.value;
  await runDecrypt();
});

async function runDecrypt(): Promise<void> {
  setActiveOperation(true);
  await showProgress('Decrypting…', 'Decrypting…');

  try {
    const request: DecryptRequest = {
      input: state.decrypt.inputPath,
      output: state.decrypt.outputPath,
    };

    if (state.decrypt.mode === 'passphrase') {
      request.passphrase = state.decrypt.passphrase;
    } else {
      request.secretKeyPath = state.decrypt.secKeyPath;
      if (state.decrypt.secKeyPassphrase) {
        request.secretKeyPassphrase = state.decrypt.secKeyPassphrase;
      }
    }

    const summary = await invoke<OperationSummary>('decrypt_container', { req: request });
    hideProgress();
    showToast({
      type: 'success',
      title: 'Decryption Complete',
      message: `Extracted to ${formatBytes(summary.outputSize ?? 0)} in ${formatDuration(summary.elapsedMs ?? 0)}`,
    });
    // Reset form
    state.decrypt.inputPath = '';
    state.decrypt.metadata = null;
    state.decrypt.mode = null;
    state.decrypt.passphrase = '';
    state.decrypt.secKeyPath = '';
    state.decrypt.secKeyPassphrase = '';
    els.decryptFileName.textContent = 'No file selected';
    els.decryptOutput.value = '';
    els.decryptPassphrase.value = '';
    els.decryptSecKey.value = '';
    els.decryptSecKeySelected.textContent = '';
    els.decryptSecKeySelected.classList.add('hidden');
    els.decryptSecPassphrase.value = '';
    els.metadataCard.classList.add('hidden');
    els.decryptFields.classList.add('hidden');
    els.btnDecrypt.disabled = true;
  } catch (err) {
    hideProgress();
    const msg = String(err);
    if (msg.includes('Cancelled')) {
      showToast({ type: 'warning', title: 'Cancelled', message: 'Decryption was cancelled' });
    } else if (msg.toLowerCase().includes('authentication') || msg.toLowerCase().includes('wrong password')) {
      showToast({ type: 'error', title: 'Wrong Passphrase', message: 'The passphrase or secret key is incorrect' });
    } else {
      showToast({ type: 'error', title: 'Decryption Failed', message: msg });
    }
  } finally {
    setActiveOperation(false);
  }
}

// --- Key Generation ---
els.btnGenerateKey.addEventListener('click', async () => {
  if (!els.keyOutput.value) {
    showToast({ type: 'error', title: 'Missing Output', message: 'Please choose an output directory' });
    return;
  }

  state.keys.namePrefix = els.keyName.value || 'qenc-key';
  state.keys.outputDir = els.keyOutput.value;
  state.keys.passphrase = els.keyPassphrase.value;

  try {
    els.btnGenerateKey.disabled = true;
    const request: KeygenRequest = {
      outputDir: state.keys.outputDir,
      namePrefix: state.keys.namePrefix,
      passphrase: state.keys.passphrase || undefined,
    };
    const summary = await invoke<KeygenSummary>('generate_keypair', { req: request });
    renderKeyResult(summary);
    showToast({ type: 'success', title: 'Keypair Generated', message: `Saved to ${summary.publicKeyPath} and ${summary.secretKeyPath}` });
  } catch (err) {
    showToast({ type: 'error', title: 'Key Generation Failed', message: String(err) });
  } finally {
    els.btnGenerateKey.disabled = false;
  }
});

function renderKeyResult(summary: KeygenSummary): void {
  els.keyResultCard.classList.remove('hidden');
  const pubPath = summary.publicKeyPath ?? '';
  const secPath = summary.secretKeyPath ?? '';
  const pubName = pubPath.split(/[/\\]/).pop() || pubPath;
  const secName = secPath.split(/[/\\]/).pop() || secPath;
  els.keyResultGrid.innerHTML = `
    <div class="key-result-row">
      <dt>Public Key</dt>
      <dd class="path-copy" id="publicKeyPath">
        <span class="path-text">${pubName}</span>
        <button type="button" class="copy-btn" data-copy="${pubPath}" aria-label="Copy path">Copy</button>
      </dd>
    </div>
    <div class="key-result-row">
      <dt>Private Key</dt>
      <dd class="path-copy" id="privateKeyPath">
        <span class="path-text">${secName}</span>
        <button type="button" class="copy-btn" data-copy="${secPath}" aria-label="Copy path">Copy</button>
      </dd>
    </div>
    <div class="key-result-row">
      <dt>SHA-256 Fingerprint</dt>
      <dd class="fingerprint-copy" id="fingerprintPath">
        <code class="fingerprint-text">${summary.fingerprint ?? ''}</code>
        <button type="button" class="copy-btn" data-copy="${summary.fingerprint ?? ''}" aria-label="Copy fingerprint">Copy</button>
      </dd>
    </div>
  `;

  els.keyResultGrid.querySelectorAll('.copy-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const text = btn.getAttribute('data-copy')!;
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        // Fallback for WebKitGTK: select-and-copy via temporary textarea
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch { /* ignore */ }
        document.body.removeChild(ta);
      }
      btn.textContent = 'Copied!';
      setTimeout(() => (btn.textContent = 'Copy'), 1500);
    });
  });
}

// --- Progress UI ---
let progressListener: (() => void) | null = null;
let elapsedInterval: number | null = null;
let progressStartMs = 0;

function formatElapsed(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const min = Math.floor(total / 60);
  const sec = total % 60;
  return `${String(min).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
}

function stageLabel(stage: string): string {
  switch (stage) {
    case 'KeyDerivation': return 'Deriving key (Argon2id / ML-KEM)…';
    case 'Archiving': return 'Reading & archiving files…';
    case 'Compressing': return 'Compressing (Zstd)…';
    case 'Encrypting': return 'Compressing & encrypting…';
    case 'Decrypting': return 'Decrypting & verifying…';
    case 'Decompressing': return 'Decompressing…';
    case 'Extracting': return 'Extracting files…';
    case 'Finalizing': return 'Finalizing…';
    default: return stage;
  }
}

async function showProgress(title: string, stage: string): Promise<void> {
  els.progressTitle.textContent = title;
  els.progressStage.textContent = stageLabel(stage) || stage;
  els.progressBar.style.width = '0%';
  els.progressPercent.textContent = '0%';
  els.progressThroughput.textContent = '0 MB/s';
  els.progressProcessed.textContent = '0 B';
  els.progressElapsed.textContent = '00:00';
  els.progressDetail.textContent = '';
  els.progressOverlay.classList.remove('hidden');
  requestAnimationFrame(() => els.progressOverlay.classList.add('show'));

  // Reset the throttle so the first event of THIS operation always passes.
  state.progressThrottle = 0;

  // Lightweight client-side elapsed timer so the clock ticks smoothly even
  // during the ~1s Argon2id key-derivation pause before bytes start streaming.
  progressStartMs = Date.now();
  if (elapsedInterval !== null) {
    window.clearInterval(elapsedInterval);
  }
  elapsedInterval = window.setInterval(() => {
    els.progressElapsed.textContent = formatElapsed(Date.now() - progressStartMs);
  }, 250);

  progressListener = await listen<ProgressEvent>('qenc://progress', (event) => {
    const now = Date.now();
    if (now - state.progressThrottle < 40) return; // ~25 updates/sec max
    state.progressThrottle = now;
    updateProgress(event.payload);
  });
}

function updateProgress(payload: ProgressEvent): void {
  const { stage, bytesProcessed, totalBytes, elapsedMs, mbPerSec } = payload;

  els.progressStage.textContent = stageLabel(stage) || stage || '';

  // Prefer the backend percent (clamped); fall back to bytes/total.
  let percent: number;
  if (typeof payload.percent === 'number' && Number.isFinite(payload.percent)) {
    percent = Math.min(100, Math.max(0, payload.percent));
  } else if (totalBytes && totalBytes > 0) {
    percent = Math.min(100, Math.max(0, Math.round((bytesProcessed / totalBytes) * 100)));
  } else {
    percent = 0;
  }

  els.progressBar.style.width = `${percent}%`;
  els.progressPercent.textContent = `${percent % 1 === 0 ? percent : percent.toFixed(1)}%`;

  if (totalBytes && totalBytes > 0) {
    els.progressProcessed.textContent = `${formatBytes(bytesProcessed ?? 0)} / ${formatBytes(totalBytes)}`;
  } else {
    els.progressProcessed.textContent = formatBytes(bytesProcessed ?? 0);
  }

  els.progressThroughput.textContent = `${(mbPerSec ?? 0).toFixed(1)} MB/s`;
  const clientElapsed = Date.now() - progressStartMs;
  const shownElapsed = Math.max(elapsedMs ?? 0, clientElapsed);
  els.progressElapsed.textContent = formatElapsed(shownElapsed);
}

function hideProgress(): void {
  els.progressOverlay.classList.remove('show');
  setTimeout(() => els.progressOverlay.classList.add('hidden'), 200);
  if (elapsedInterval !== null) {
    window.clearInterval(elapsedInterval);
    elapsedInterval = null;
  }
  if (progressListener) {
    progressListener();
    progressListener = null;
  }
}

// --- Cancel ---
els.btnCancel.addEventListener('click', async () => {
  try {
    await invoke<boolean>('cancel_operation');
  } catch (err) {
    showToast({ type: 'error', title: 'Cancel Failed', message: String(err) });
  }
});

function setActiveOperation(active: boolean): void {
  state.activeOperation = active;
  els.btnEncrypt.disabled = active || state.encrypt.files.length === 0;
  els.btnDecrypt.disabled = active || !state.decrypt.inputPath;
  els.btnGenerateKey.disabled = active;
  if (active) {
    document.body.style.cursor = 'progress';
  } else {
    document.body.style.cursor = '';
  }
}

// --- Mobile adaptations ---
function applyMobileCopy(): void {
  // Touch-friendly drop-zone copy (no drag-and-drop on Android).
  const encZone = document.getElementById('encryptDropZone');
  if (encZone) {
    const text = encZone.querySelector('.drop-text');
    const hint = encZone.querySelector('.drop-hint');
    if (text) text.textContent = 'Tap to Select Files';
    if (hint) hint.textContent = 'Photos, documents and more';
  }
  const decZone = document.getElementById('decryptDropZone');
  if (decZone) {
    const text = decZone.querySelector('.drop-text');
    const hint = decZone.querySelector('.drop-hint');
    if (text) text.textContent = 'Tap to Select .qenc File';
    if (hint) hint.textContent = 'Pick from your storage';
  }
}

function showUltraHintIfNeeded(): void {
  // Subtle, non-blocking hint when choosing the heaviest profile on mobile.
  if (state.encrypt.profile === 'ultra' && state.isMobile) {
    showToast({
      type: 'info',
      title: 'Ultra compression',
      message: 'Zstd L19 uses more RAM and battery on mobile.',
    });
  }
}

async function prefillMobileDefaults(): Promise<void> {
  const paths = await invoke<DefaultPaths>('get_default_paths');
  // Suggest a container name based on the first picked input, if any.
  const suggest = () => {
    const base = state.encrypt.files[0]?.name ?? 'archive';
    const stem = base.replace(/\.[^./\\]+$/, '') || 'archive';
    return `${paths.encryptedDir}/${stem}.qenc`;
  };
  if (!els.encryptOutput.value && paths.encryptedDir) els.encryptOutput.value = suggest();
  if (!els.decryptOutput.value && paths.decryptedDir) els.decryptOutput.value = paths.decryptedDir;
  if (!els.keyOutput.value && paths.keysDir) els.keyOutput.value = paths.keysDir;
}

// --- Initialize ---
async function init(): Promise<void> {
  try {
    const sysInfo = await invoke<SystemInfo>('get_system_info');
    console.log('QENC System Info:', sysInfo);
    state.isMobile = !!sysInfo.isMobile;
    state.argonRecommendation = sysInfo.recommendedArgon2Profile ?? 'desktop';
    if (state.isMobile) {
      document.body.classList.add('is-mobile');
      applyMobileCopy();
    }
  } catch (err) {
    console.warn('Failed to get system info:', err);
  }

  // Check for pending .qenc file to open (from double-click or CLI)
  try {
    const pendingPath = await invoke<string | null>('take_pending_open_file');
    if (pendingPath) {
      console.log('Opening pending .qenc file:', pendingPath);
      // Switch to Decrypt tab
      switchTab('decrypt');
      // Populate the decrypt file input
      state.decrypt.inputPath = pendingPath;
      (document.getElementById('decryptFileName') as HTMLElement).textContent = pendingPath;
      (document.getElementById('decryptFileName') as HTMLElement).classList.remove('hidden');
      // Trigger inspection
      await loadDecryptFile(pendingPath);
    }
  } catch (err) {
    console.warn('Failed to check pending open file:', err);
  }

  // Setup drag-and-drop (desktop only; skip gracefully on Android where
// onDragDropEvent is unsupported and taps replace drags)
  if (!state.isMobile) {
    try {
      setupTauriDragAndDrop();
    } catch (err) {
      console.warn('Drag-and-drop registration skipped:', err);
    }
  }

  // Setup drop zone click handlers
  setupDropZoneClickHandlers();

  // Pre-fill writable default output paths on mobile (2-tap encrypt/decrypt).
  if (state.isMobile) {
    try {
      await prefillMobileDefaults();
    } catch (err) {
      console.warn('Failed to prefill mobile default paths:', err);
    }
  }

  // Wire up compression profile + security mode radio selectors
  els.profileRadios.forEach((radio) => {
    radio.addEventListener('change', () => {
      if (radio.checked) {
        state.encrypt.profile = radio.value as 'turbo' | 'balanced' | 'ultra';
        showUltraHintIfNeeded();
      }
    });
  });

  els.modeRadios.forEach((radio) => {
    radio.addEventListener('change', () => {
      if (radio.checked) {
        // HTML value is "passphrase" | "hybrid"; state uses "passphrase" | "hybridPqc"
        state.encrypt.mode = radio.value === 'hybrid' ? 'hybridPqc' : 'passphrase';
        els.passphraseFields.classList.toggle('hidden', state.encrypt.mode !== 'passphrase');
        els.hybridFields.classList.toggle('hidden', state.encrypt.mode !== 'hybridPqc');
        // Clear any stale passphrase mismatch indicator when switching modes
        els.matchIndicator.textContent = '';
      }
    });
  });

  // Setup file picker buttons
  els.browsePubkey.addEventListener('click', () => pickFile(els.pubkeyInput, els.pubkeySelected, [{ name: 'QENC Public Key', extensions: ['qenc.pub'] }]));
  els.browseEncryptOutput.addEventListener('click', () => pickSaveFile(els.encryptOutput, [{ name: 'QENC Container', extensions: ['qenc'] }], 'archive.qenc'));
  els.browseDecryptSecKey.addEventListener('click', () => pickFile(els.decryptSecKey, els.decryptSecKeySelected, [{ name: 'QENC Secret Key', extensions: ['qenc.sec'] }]));
  els.browseDecryptOutput.addEventListener('click', () => pickDirectory(els.decryptOutput));
  els.browseKeyOutput.addEventListener('click', () => pickDirectory(els.keyOutput));

  // Passphrase strength meter
  els.passphraseInput.addEventListener('input', () => {
    const { score, label, color } = calculatePassphraseStrength(els.passphraseInput.value);
    const fill = els.passphraseStrength.querySelector('.strength-fill') as HTMLElement;
    fill.style.width = `${score}%`;
    fill.style.backgroundColor = color;
    els.strengthText.textContent = label;
    els.strengthText.style.color = color;

    // Check match
    if (els.passphraseConfirm.value) {
      checkPassphraseMatch();
    }
  });

  els.passphraseConfirm.addEventListener('input', checkPassphraseMatch);
}

init();