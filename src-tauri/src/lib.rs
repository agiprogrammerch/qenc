//! QENC Tauri v2 GUI Library
//!
//! Provides the IPC command layer on top of `qenc-core` for the desktop GUI.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::or_fun_call,
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::option_if_let_else,
    clippy::multiple_crate_versions,
)]

use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use qenc_core::{
    crypto::{generate_full_hybrid_keypair, save_public_key, save_full_secret_key},
    format::inspect_header,
    archive::estimate_input_size,
    KeyMode, CompressionProfile,
    decrypt_stream, encrypt_stream, encrypt_named_streams, NamedStreamInput,
    EncryptOptions, DecryptOptions, ProgressEvent, QencError,
};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tauri::{
    AppHandle, Emitter, Manager, Runtime, State,
    async_runtime::spawn_blocking,
};
use tauri_plugin_fs::{FsExt, FilePath, OpenOptions as FsOpenOptions};
use thiserror::Error;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
#[allow(clippy::large_stack_frames)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(CancelState::default())
        .manage(PendingOpenFile::default())
        .invoke_handler(tauri::generate_handler![
            inspect_container,
            inspect_input_paths,
            encrypt_files,
            decrypt_container,
            generate_keypair,
            cancel_operation,
            get_system_info,
            get_default_paths,
            take_pending_open_file,
        ])
        .setup(|app| {
            // On Android/Windows the desktop-only block below compiles away,
            // which would leave `app` unused; borrow it once so every target
            // builds with zero warnings.
            let _ = &app;

            // Check for .qenc file passed as command-line argument
            #[cfg(desktop)]
            {
                let args: Vec<String> = std::env::args().collect();
                if args.len() > 1 {
                    let path = &args[1];
                    if path.to_lowercase().ends_with(".qenc") {
                        if let Ok(canonical) = std::fs::canonicalize(path) {
                            let pending = app.state::<PendingOpenFile>();
                            *pending.0.lock().unwrap() = Some(canonical.to_string_lossy().to_string());
                        }
                    }
                }
            }

            #[cfg(all(debug_assertions, desktop))]
            {
                if let Some(window) = app.get_webview_window("main") {
                    window.open_devtools();
                }
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// --- Cancellation State ---

#[derive(Default)]
pub struct CancelState {
    pub inner: Mutex<Option<Arc<std::sync::atomic::AtomicBool>>>,
}

impl CancelState {
    pub fn get_or_create(&self) -> Arc<std::sync::atomic::AtomicBool> {
        let mut guard = self.inner.lock().unwrap();
        if let Some(cancel) = guard.as_ref() {
            cancel.clone()
        } else {
            let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
            *guard = Some(cancel.clone());
            cancel
        }
    }

    pub fn take(&self) -> Option<Arc<std::sync::atomic::AtomicBool>> {
        self.inner.lock().unwrap().take()
    }
}

/// RAII guard that guarantees the `CancelState` token is cleared on drop,
/// so an early return, error, or panic can NEVER leave the app permanently
/// stuck in "operation in progress".
struct CancelGuard<'a> {
    state: &'a CancelState,
}

impl<'a> CancelGuard<'a> {
    const fn new(state: &'a CancelState) -> Self {
        Self { state }
    }
}

impl Drop for CancelGuard<'_> {
    fn drop(&mut self) {
        // Always clear the token (take() sets it back to None).
        self.state.take();
    }
}

// --- Pending Open File State ---

#[derive(Default)]
pub struct PendingOpenFile(pub Mutex<Option<String>>);

impl PendingOpenFile {
    pub fn take(&self) -> Option<String> {
        self.0.lock().unwrap().take()
    }
}

// --- Android Scoped Storage / URI helpers ---

/// Detects Android SAF (`content://`) or `file://` URIs.
#[must_use]
pub fn is_content_or_file_uri(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.starts_with("content://") || lower.starts_with("file://")
}

/// Opens a readable handle for a filesystem path OR a `content://` / `file://` URI.
/// Desktop paths are opened directly with `std` so desktop behavior is unchanged.
pub fn open_readable_handle<R: Runtime>(
    app: &AppHandle<R>,
    path_or_uri: &str,
) -> Result<std::fs::File, String> {
    if is_content_or_file_uri(path_or_uri) {
        let url = url::Url::parse(path_or_uri)
            .map_err(|e| format!("Invalid URI {path_or_uri}: {e}"))?;
        app.fs()
            .open(FilePath::Url(url), FsOpenOptions::new().read(true).to_owned())
            .map_err(|e| format!("Failed to open {path_or_uri}: {e}"))
    } else {
        std::fs::File::open(path_or_uri).map_err(|e| format!("Failed to open {path_or_uri}: {e}"))
    }
}

/// Opens a writable handle (create+truncate) for a URI or filesystem path.
pub fn open_writable_handle<R: Runtime>(
    app: &AppHandle<R>,
    path_or_uri: &str,
) -> Result<std::fs::File, String> {
    if is_content_or_file_uri(path_or_uri) {
        let url = url::Url::parse(path_or_uri)
            .map_err(|e| format!("Invalid URI {path_or_uri}: {e}"))?;
        app.fs()
            .open(
                FilePath::Url(url),
                FsOpenOptions::new().write(true).create(true).truncate(true).to_owned(),
            )
            .map_err(|e| format!("Failed to open {path_or_uri} for writing: {e}"))
    } else {
        std::fs::File::create(path_or_uri)
            .map_err(|e| format!("Failed to create {path_or_uri}: {e}"))
    }
}

/// Returns the exact byte length of a URI/path handle (seeks to the end).
#[must_use]
pub fn stream_len(mut file: &std::fs::File) -> u64 {
    file.seek(SeekFrom::End(0)).unwrap_or(0)
}

/// Extracts a clean display filename from a path or Android SAF URI.
///
/// Percent-decodes segments and strips SAF volume prefixes
/// (`content://.../document/primary%3ADownload%2Freport%20final.pdf` -> `report final.pdf`).
#[must_use]
pub fn extract_display_name(path_or_uri: &str, fallback_index: usize) -> String {
    let last_raw = path_or_uri.rsplit('/').next().unwrap_or(path_or_uri);
    let decoded = match urlencoding::decode(last_raw) {
        Ok(cow) => cow.into_owned(),
        Err(_) => last_raw.to_string(),
    };
    let final_seg = decoded.rsplit('/').next().unwrap_or(&decoded).rsplit('\\').next().unwrap_or(&decoded);
    let trimmed = final_seg.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return format!("input_{fallback_index}");
    }
    trimmed.to_string()
}

fn is_writable_dir(p: &std::path::Path) -> bool {
    let probe = p.join(".qenc_write_test");
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Resolves a writable QENC workspace directory.
///
/// Prefers public `document_dir()/QENC` then `download_dir()/QENC` (only if
/// actually writable under Android 10–16 Scoped Storage), falling back to
/// `app_data_dir()/QENC` so we never throw EACCES.
pub fn resolve_mobile_storage_root<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(dir) = app.path().document_dir() {
        candidates.push(dir.join("QENC"));
    }
    if let Ok(dir) = app.path().download_dir() {
        candidates.push(dir.join("QENC"));
    }
    if let Ok(dir) = app.path().app_data_dir() {
        candidates.push(dir.join("QENC"));
    }
    for candidate in candidates {
        if std::fs::create_dir_all(&candidate).is_ok() && is_writable_dir(&candidate) {
            return Ok(candidate);
        }
    }
    Err("No writable QENC storage root is available".into())
}

/// Returns the default writable `encrypted`/`decrypted`/`keys` directories,
/// creating them if necessary.
fn default_paths_response<R: Runtime>(app: &AppHandle<R>) -> Result<DefaultPathsResponse, String> {
    let root = resolve_mobile_storage_root(app)?;
    let encrypted = root.join("encrypted");
    let decrypted = root.join("decrypted");
    let keys = root.join("keys");
    for dir in [&encrypted, &decrypted, &keys] {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Failed to create {}: {e}", dir.display()))?;
    }
    Ok(DefaultPathsResponse {
        encrypted_dir: encrypted.to_string_lossy().into_owned(),
        decrypted_dir: decrypted.to_string_lossy().into_owned(),
        keys_dir: keys.to_string_lossy().into_owned(),
    })
}

// --- IPC Types ---

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Argon2ParamsDto {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct QencMetadataDto {
    pub version: u8,
    pub key_mode: KeyModeDto,
    pub compression_profile: CompressionProfileDto,
    pub chunk_size: u32,
    pub original_size: u64,
    pub argon2_params: Option<Argon2ParamsDto>,
    pub ephemeral_x25519_pk: Option<Vec<u8>>,
    pub mlkem_ciphertext: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum KeyModeDto {
    Passphrase,
    HybridPqc,
}

impl From<KeyMode> for KeyModeDto {
    fn from(m: KeyMode) -> Self {
        match m {
            KeyMode::Passphrase => Self::Passphrase,
            KeyMode::HybridPqc => Self::HybridPqc,
        }
    }
}

impl From<KeyModeDto> for KeyMode {
    fn from(m: KeyModeDto) -> Self {
        match m {
            KeyModeDto::Passphrase => Self::Passphrase,
            KeyModeDto::HybridPqc => Self::HybridPqc,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum CompressionProfileDto {
    Turbo,
    Balanced,
    Ultra,
}

impl From<CompressionProfile> for CompressionProfileDto {
    fn from(p: CompressionProfile) -> Self {
        match p {
            CompressionProfile::Turbo => Self::Turbo,
            CompressionProfile::Balanced => Self::Balanced,
            CompressionProfile::Ultra => Self::Ultra,
        }
    }
}

impl From<CompressionProfileDto> for CompressionProfile {
    fn from(p: CompressionProfileDto) -> Self {
        match p {
            CompressionProfileDto::Turbo => Self::Turbo,
            CompressionProfileDto::Balanced => Self::Balanced,
            CompressionProfileDto::Ultra => Self::Ultra,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InspectResponseDto {
    pub metadata: QencMetadataDto,
    pub file_size: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEventDto {
    pub stage: String,
    pub percent: f64,
    pub bytes_processed: u64,
    pub total_bytes: Option<u64>,
    pub output_bytes: u64,
    pub elapsed_ms: u64,
    pub mb_per_sec: f64,
}

impl From<ProgressEvent> for ProgressEventDto {
    fn from(e: ProgressEvent) -> Self {
        Self {
            stage: format!("{:?}", e.stage),
            percent: e.percent,
            bytes_processed: e.bytes_processed,
            total_bytes: e.total_bytes,
            output_bytes: e.output_bytes,
            elapsed_ms: e.elapsed_ms,
            mb_per_sec: e.mb_per_sec,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptRequestDto {
    pub inputs: Vec<String>,
    pub output: String,
    pub mode: KeyModeDto,
    pub profile: CompressionProfileDto,
    pub passphrase: Option<String>,
    pub recipient_pubkey_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptRequestDto {
    pub input: String,
    pub output: String,
    pub passphrase: Option<String>,
    pub secret_key_path: Option<String>,
    pub secret_key_passphrase: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationSummaryDto {
    pub output_size: u64,
    pub compression_ratio_percent: f64,
    pub elapsed_ms: u64,
    pub avg_mb_per_sec: f64,
    pub output_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeygenRequestDto {
    pub output_dir: String,
    pub name_prefix: String,
    pub passphrase: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeygenSummaryDto {
    pub public_key_path: String,
    pub secret_key_path: String,
    pub fingerprint: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfoDto {
    pub platform: String,
    pub is_mobile: bool,
    pub recommended_argon2_profile: String,
    pub engine_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultPathsResponse {
    pub encrypted_dir: String,
    pub decrypted_dir: String,
    pub keys_dir: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputPathInfoDto {
    pub path: String,
    pub name: String,
    pub size_bytes: u64,
    pub is_dir: bool,
    pub file_count: u64,
}

// --- Error Handling ---

#[derive(Error, Debug)]
pub enum GuiError {
    #[error("QENC core error: {0}")]
    Core(#[from] QencError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("{0}")]
    Storage(String),
    #[error("Operation cancelled")]
    Cancelled,
    #[error("Operation already in progress")]
    AlreadyInProgress,
}

impl Serialize for GuiError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl From<String> for GuiError {
    fn from(s: String) -> Self {
        Self::Storage(s)
    }
}

type GuiResult<T> = std::result::Result<T, GuiError>;

// --- Progress Emission ---

/// Forwards a qenc-core progress event to the frontend.
///
/// The core pipeline already throttles to ~16 updates/sec, so we forward EVERY
/// event directly with no extra throttling. (The previous throttle used
/// `Instant::now().elapsed()`, which is always ~0 ms, so it silently dropped
/// every event after the first — that was the root cause of the progress bar
/// freezing at 0%.)
fn emit_progress<R: Runtime>(app: &AppHandle<R>, event: ProgressEvent) {
    let _ = app.emit("qenc://progress", ProgressEventDto::from(event));
}

// --- IPC Commands ---

#[tauri::command]
async fn inspect_container<R: Runtime>(
    app: AppHandle<R>,
    path: String,
) -> GuiResult<InspectResponseDto> {
    let app2 = app.clone();
    let path2 = path.clone();
    let (metadata, file_size) = spawn_blocking(move || {
        let mut file = open_readable_handle(&app2, &path2).map_err(GuiError::Storage)?;
        let len = stream_len(&file);
        file.seek(SeekFrom::Start(0)).map_err(GuiError::Io)?;
        let info = inspect_header(&mut file)?;
        Ok::<_, GuiError>((info, len))
    })
    .await
    .map_err(|e| GuiError::InvalidArgument(format!("Join error: {e}")))??;

    let dto = InspectResponseDto {
        metadata: QencMetadataDto {
            version: metadata.version,
            key_mode: metadata.key_mode.into(),
            compression_profile: metadata.compression_profile.into(),
            chunk_size: metadata.chunk_size,
            original_size: metadata.original_size,
            argon2_params: metadata.argon2_params.map(|p| Argon2ParamsDto {
                m_cost_kib: p.m_cost_kib,
                t_cost: p.t_cost,
                p_cost: p.p_cost,
            }),
            ephemeral_x25519_pk: metadata.ephemeral_x25519_pk.map(|p| p.to_vec()),
            mlkem_ciphertext: metadata.mlkem_ciphertext,
        },
        file_size,
    };

    Ok(dto)
}

#[tauri::command]
async fn inspect_input_paths<R: Runtime>(
    app: AppHandle<R>,
    paths: Vec<String>,
) -> GuiResult<Vec<InputPathInfoDto>> {
    let app2 = app.clone();
    let results = spawn_blocking(move || {
        let mut results = Vec::new();
        for (idx, path_str) in paths.into_iter().enumerate() {
            if is_content_or_file_uri(&path_str) {
                // Android SAF `content://` / `file://` URI: open + exact length.
                let file = open_readable_handle(&app2, &path_str).map_err(GuiError::Storage)?;
                let len = stream_len(&file);
                let name = extract_display_name(&path_str, idx);
                results.push(InputPathInfoDto {
                    path: path_str,
                    name,
                    size_bytes: len,
                    is_dir: false,
                    file_count: 1,
                });
                continue;
            }

            let path = PathBuf::from(&path_str);
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&path_str)
                .to_string();

            let (size_bytes, is_dir, file_count) = if path.is_dir() {
                let mut total_size = 0u64;
                let mut count = 0u64;
                if let Ok(entries) = std::fs::read_dir(&path) {
                    for entry in entries.flatten() {
                        if let Ok(metadata) = entry.metadata() {
                            if metadata.is_file() {
                                total_size += metadata.len();
                                count += 1;
                            } else if metadata.is_dir() {
                                count += 1;
                            }
                        }
                    }
                }
                (total_size, true, count)
            } else {
                let metadata = std::fs::metadata(&path);
                let size = metadata.map_or(0, |m| m.len());
                (size, false, 0)
            };

            results.push(InputPathInfoDto {
                path: path_str,
                name,
                size_bytes,
                is_dir,
                file_count,
            });
        }
        Ok::<Vec<InputPathInfoDto>, GuiError>(results)
    })
    .await
    .map_err(|e| GuiError::InvalidArgument(format!("Join error: {e}")))??;

    Ok(results)
}

#[tauri::command]
async fn encrypt_files<R: Runtime>(
    app: AppHandle<R>,
    req: EncryptRequestDto,
    cancel_state: State<'_, CancelState>,
) -> GuiResult<OperationSummaryDto> {
    // Create/clear the cancel token and install a guard so the token is ALWAYS
    // reset when this function returns (success, error, or cancellation).
    let cancel_token = cancel_state.get_or_create();
    cancel_token.store(false, std::sync::atomic::Ordering::Relaxed);
    let _cancel_guard = CancelGuard::new(&cancel_state);

    // Clone for the blocking task
    let cancel_token_clone = cancel_token.clone();
    let app_clone = app.clone();

    let inputs: Vec<PathBuf> = req.inputs.iter().map(PathBuf::from).collect();
    let mode = req.mode.into();
    let profile = req.profile.into();
    let output_is_uri = is_content_or_file_uri(&req.output);
    let has_uri_input = req.inputs.iter().any(|p| is_content_or_file_uri(p));

    // If the recipient public key is a content:// / file:// URI, materialize the
    // tiny 1600-byte .qenc.pub into a temp file so qenc-core's path-based loader
    // can use it unchanged.
    let recipient_pubkey_path = match req.recipient_pubkey_path.as_ref() {
        Some(pk) if is_content_or_file_uri(pk) => {
            let app_pk = app.clone();
            let pk2 = pk.clone();
            let bytes = spawn_blocking(move || {
                let mut f = open_readable_handle(&app_pk, &pk2).map_err(GuiError::Storage)?;
                let mut buf = Vec::new();
                f.read_to_end(&mut buf).map_err(GuiError::Io)?;
                Ok::<_, GuiError>(buf)
            })
            .await
            .map_err(|e| GuiError::InvalidArgument(format!("Join error: {e}")))??;
            if bytes.len() != 1600 {
                return Err(GuiError::Storage(format!(
                    "Public key must be 1600 bytes, got {}",
                    bytes.len()
                )));
            }
            let tmp = std::env::temp_dir().join(format!("qenc-pub-{}.bin", uuid::Uuid::new_v4()));
            std::fs::write(&tmp, &bytes).map_err(GuiError::Io)?;
            Some(tmp.to_string_lossy().into_owned())
        }
        other => other.cloned(),
    };

    let start = Instant::now();

    let summary = if has_uri_input {
        // --- Android SAF named-stream encryption (zero-copy from Read handles) ---
        let app_s = app.clone();
        let app_p = app.clone();
        let req_inputs = req.inputs.clone();
        let cancel = cancel_token_clone.clone();
        let mut core_opts = EncryptOptions {
            mode,
            profile,
            passphrase: req.passphrase.clone(),
            recipient_pubkey_path: recipient_pubkey_path.clone(),
            ..Default::default()
        };
        core_opts.original_size_hint = None;
        core_opts.argon2_mobile_hint = Some(cfg!(mobile));

        // Resolve the output writer (content:// URI, blank-on-mobile default, or path).
        let (writer_file, out_display) = if output_is_uri {
            let app_w = app.clone();
            let out = req.output.clone();
            let f = spawn_blocking(move || open_writable_handle(&app_w, &out).map_err(GuiError::Storage))
                .await
                .map_err(|e| GuiError::InvalidArgument(format!("Join error: {e}")))??;
            (f, req.output.clone())
        } else if req.output.is_empty() && cfg!(mobile) {
            let root = resolve_mobile_storage_root(&app)?;
            let dir = root.join("encrypted");
            std::fs::create_dir_all(&dir).map_err(GuiError::Io)?;
            let p = dir.join(format!("qenc-{}.qenc", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())));
            (std::fs::File::create(&p).map_err(GuiError::Io)?, p.to_string_lossy().into_owned())
        } else {
            let out = req.output.clone();
            (std::fs::File::create(&out).map_err(GuiError::Io)?, out)
        };

        let res = spawn_blocking(move || {
            let mut entries = Vec::new();
            for (idx, p) in req_inputs.iter().enumerate() {
                let mut f = open_readable_handle(&app_s, p).map_err(QencError::InvalidArgument)?;
                let size = stream_len(&f);
                f.seek(SeekFrom::Start(0)).map_err(QencError::Io)?;
                let name = extract_display_name(p, idx);
                entries.push(NamedStreamInput { name, size, reader: Box::new(f) });
            }
            encrypt_named_streams(
                entries,
                std::io::BufWriter::new(writer_file),
                &core_opts,
                Some(Box::new(move |event| emit_progress(&app_p, event))),
                cancel,
            )
        })
        .await
        .map_err(|e| GuiError::InvalidArgument(format!("Join error: {e}")))?;

        match res {
            Ok(stats) => {
                let output_size = if output_is_uri {
                    stats.output_size
                } else {
                    std::fs::metadata(&out_display).map_or(stats.output_size, |m| m.len())
                };
                OperationSummaryDto {
                    output_size,
                    compression_ratio_percent: stats.compression_ratio_percent,
                    elapsed_ms: stats.elapsed_ms,
                    avg_mb_per_sec: stats.avg_mb_per_sec,
                    output_path: out_display,
                }
            }
            Err(e) => {
                if !output_is_uri {
                    let _ = std::fs::remove_file(&out_display);
                }
                return Err(GuiError::Core(e));
            }
        }
    } else {
        // --- Desktop path encryption (behavior unchanged) ---
        let inputs_for_estimate = inputs.clone();
        let original_size_estimate = spawn_blocking(move || estimate_input_size(&inputs_for_estimate))
            .await
            .unwrap_or(0);

        let options = EncryptOptions {
            mode,
            profile,
            passphrase: req.passphrase,
            recipient_pubkey_path: recipient_pubkey_path.clone(),
            progress_cb: Some(Box::new(move |event| {
                emit_progress(&app_clone, event);
            })),
            cancel: Some(cancel_token_clone),
            original_size_hint: Some(original_size_estimate),
            argon2_mobile_hint: Some(cfg!(mobile)),
        };

        let output = PathBuf::from(&req.output);
        let output_for_metadata = output.clone();
        let encrypt_result = spawn_blocking(move || {
            let encrypt_res = match std::fs::File::create(&output) {
                Ok(writer) => encrypt_stream(&inputs, std::io::BufWriter::new(writer), options),
                Err(e) => Err(QencError::Io(e)),
            };
            (encrypt_res, output)
        })
        .await
        .map_err(|e| GuiError::InvalidArgument(format!("Join error: {e}")))?;

        let (encrypt_result, output_path) = encrypt_result;
        let elapsed_ms = start.elapsed().as_millis() as u64;

        if let Err(e) = encrypt_result {
            let _ = std::fs::remove_file(&output_path);
            return Err(GuiError::Core(e));
        }

        let output_size = std::fs::metadata(&output_for_metadata)?.len();
        let compression_ratio_percent = if original_size_estimate > 0 {
            (output_size as f64 / original_size_estimate as f64) * 100.0
        } else {
            100.0
        };
        let avg_mb_per_sec = if elapsed_ms > 0 {
            (original_size_estimate as f64 / 1_048_576.0) / (elapsed_ms as f64 / 1000.0)
        } else {
            0.0
        };

        OperationSummaryDto {
            output_size,
            compression_ratio_percent,
            elapsed_ms,
            avg_mb_per_sec,
            output_path: output_path.to_string_lossy().into_owned(),
        }
    };

    Ok(summary)
}

#[tauri::command]
async fn decrypt_container<R: Runtime>(
    app: AppHandle<R>,
    req: DecryptRequestDto,
    cancel_state: State<'_, CancelState>,
) -> GuiResult<OperationSummaryDto> {
    // Create/clear cancel token + RAII guard so the app never gets stuck.
    let cancel_token = cancel_state.get_or_create();
    cancel_token.store(false, std::sync::atomic::Ordering::Relaxed);
    let _cancel_guard = CancelGuard::new(&cancel_state);

    let cancel_token_clone = cancel_token.clone();
    let app_clone = app.clone();

    // Materialize a content:// / file:// secret key into a temp file so qenc-core's
    // path-based loader can use it (the .qenc.sec is tiny).
    let secret_key_path = match req.secret_key_path.as_ref() {
        Some(sk) if is_content_or_file_uri(sk) => {
            let app_sk = app.clone();
            let sk2 = sk.clone();
            let bytes = spawn_blocking(move || {
                let mut f = open_readable_handle(&app_sk, &sk2).map_err(GuiError::Storage)?;
                let mut buf = Vec::new();
                f.read_to_end(&mut buf).map_err(GuiError::Io)?;
                Ok::<_, GuiError>(buf)
            })
            .await
            .map_err(|e| GuiError::InvalidArgument(format!("Join error: {e}")))??;
            let tmp = std::env::temp_dir().join(format!("qenc-sec-{}.bin", uuid::Uuid::new_v4()));
            std::fs::write(&tmp, &bytes).map_err(GuiError::Io)?;
            Some(tmp.to_string_lossy().into_owned())
        }
        other => other.cloned(),
    };

    // Determine the extraction directory. On mobile with no explicit folder,
    // auto-create `<mobile_root>/decrypted/<stem>_<timestamp>`.
    let output = if req.output.is_empty() && cfg!(mobile) {
        let root = resolve_mobile_storage_root(&app)?;
        let stem = PathBuf::from(extract_display_name(&req.input, 0))
            .file_stem()
            .map_or_else(|| "qenc".into(), |s| s.to_string_lossy().into_owned());
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        root.join("decrypted").join(format!("{stem}_{ts}"))
    } else {
        PathBuf::from(&req.output)
    };
    std::fs::create_dir_all(&output).map_err(GuiError::Io)?;

    let options = DecryptOptions {
        passphrase: req.passphrase,
        secret_key_path,
        secret_key_passphrase: req.secret_key_passphrase,
        progress_cb: Some(Box::new(move |event| {
            emit_progress(&app_clone, event);
        })),
        cancel: Some(cancel_token_clone),
        input_size_hint: None,
    };

    let start = Instant::now();
    let output_for_size = output.clone();
    let output_str = output.to_string_lossy().into_owned();

    // Open the .qenc source (URI-aware), measure its exact size for linear progress.
    let app_r2 = app.clone();
    let input_uri2 = req.input.clone();
    let source = spawn_blocking(move || open_readable_handle(&app_r2, &input_uri2).map_err(GuiError::Storage))
    .await
    .map_err(|e| GuiError::InvalidArgument(format!("Join error: {e}")))??;
    let input_size_hint = stream_len(&source);

    let mut opts = options;
    opts.input_size_hint = Some(input_size_hint);
    let opts2 = opts;

    let result = spawn_blocking(move || decrypt_stream(source, &output_for_size, opts2))
        .await
        .map_err(|e| GuiError::InvalidArgument(format!("Join error: {e}")))?;

    let elapsed_ms = start.elapsed().as_millis() as u64;

    // On error/cancellation, surface it cleanly.
    result?;

    // Compute the real extracted size by walking the output directory.
    let output_for_size2 = output.clone();
    let extracted_size = spawn_blocking(move || estimate_input_size(std::slice::from_ref(&output_for_size2)))
        .await
        .unwrap_or(0);

    let avg_mb_per_sec = if elapsed_ms > 0 {
        (extracted_size as f64 / 1_048_576.0) / (elapsed_ms as f64 / 1000.0)
    } else {
        0.0
    };

    let summary = OperationSummaryDto {
        output_size: extracted_size,
        compression_ratio_percent: 100.0,
        elapsed_ms,
        avg_mb_per_sec,
        output_path: output_str,
    };

    Ok(summary)
}

#[tauri::command]
async fn generate_keypair<R: Runtime>(app: AppHandle<R>, req: KeygenRequestDto) -> GuiResult<KeygenSummaryDto> {
    // On mobile with no explicit directory, default to `<mobile_root>/keys/`.
    let output_dir = if req.output_dir.is_empty() && cfg!(mobile) {
        resolve_mobile_storage_root(&app)?.join("keys")
    } else {
        PathBuf::from(&req.output_dir)
    };
    std::fs::create_dir_all(&output_dir)?;

    // Generate the FULL Hybrid keypair. The secret key MUST contain the complete
    // ML-KEM-1024 decapsulation key (3200 bytes) or it cannot decrypt anything.
    let (public, secret) = generate_full_hybrid_keypair()?;

    let pub_path = output_dir.join(format!("{}.qenc.pub", req.name_prefix));
    let sec_path = output_dir.join(format!("{}.qenc.sec", req.name_prefix));

    // Save full 3200-byte secret key so it is actually usable for decryption.
    save_public_key(&pub_path, &public)?;
    save_full_secret_key(&sec_path, &secret, req.passphrase.as_deref())?;

    // Compute SHA-256 fingerprint of the public key bytes.
    let mut hasher = Sha256::new();
    hasher.update(public.to_bytes());
    let fingerprint = format!("{:x}", hasher.finalize());

    Ok(KeygenSummaryDto {
        public_key_path: pub_path.to_string_lossy().to_string(),
        secret_key_path: sec_path.to_string_lossy().to_string(),
        fingerprint,
    })
}

#[tauri::command]
async fn cancel_operation(cancel_state: State<'_, CancelState>) -> GuiResult<bool> {
    let cancel_token = cancel_state.get_or_create();
    cancel_token.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(true)
}

#[tauri::command]
async fn get_system_info() -> GuiResult<SystemInfoDto> {
    let platform = match std::env::consts::OS {
        "linux" => "linux",
        "windows" => "windows",
        "macos" => "macos",
        "android" => "android",
        "ios" => "ios",
        _ => "unknown",
    };
    let is_mobile = cfg!(target_os = "android") || cfg!(target_os = "ios");

    Ok(SystemInfoDto {
        platform: platform.to_string(),
        is_mobile,
        recommended_argon2_profile: if is_mobile { "mobile" } else { "desktop" }.to_string(),
        engine_version: "QENC v1 | X25519 + ML-KEM-1024 + XChaCha20-Poly1305 + Zstd".to_string(),
    })
}

#[tauri::command]
async fn get_default_paths<R: Runtime>(app: AppHandle<R>) -> GuiResult<DefaultPathsResponse> {
    Ok(default_paths_response(&app)?)
}

#[tauri::command]
async fn take_pending_open_file(state: State<'_, PendingOpenFile>) -> Result<Option<String>, String> {
    Ok(state.take())
}
#[cfg(test)]
mod ipc_contract_tests {
    use super::*;
    use serde_json::json;

    // ---- 1. Deserialize EXACT JSON payloads produced by ui/src/main.ts ----

    #[test]
    fn deserialize_encrypt_request_passphrase() {
        // Exactly the object ui/src/main.ts sends for invoke('encrypt_files', { req })
        let payload = json!({
            "inputs": ["/home/user/doc.txt", "/home/user/photos"],
            "output": "/home/user/out.qenc",
            "mode": "passphrase",
            "profile": "balanced",
            "passphrase": "correct horse battery staple"
        });
        let req: EncryptRequestDto = serde_json::from_value(payload).expect("deserialize EncryptRequestDto");
        assert_eq!(req.inputs.len(), 2);
        assert_eq!(req.output, "/home/user/out.qenc");
        assert!(matches!(req.mode, KeyModeDto::Passphrase));
        assert!(matches!(req.profile, CompressionProfileDto::Balanced));
        assert_eq!(req.passphrase.as_deref(), Some("correct horse battery staple"));
        assert!(req.recipient_pubkey_path.is_none());
    }

    #[test]
    fn deserialize_encrypt_request_hybrid() {
        let payload = json!({
            "inputs": ["/home/user/doc.txt"],
            "output": "/home/user/out.qenc",
            "mode": "hybridPqc",
            "profile": "ultra",
            "recipientPubkeyPath": "/home/user/keys/qenc-key.qenc.pub"
        });
        let req: EncryptRequestDto = serde_json::from_value(payload).expect("deserialize EncryptRequestDto");
        assert!(matches!(req.mode, KeyModeDto::HybridPqc));
        assert!(matches!(req.profile, CompressionProfileDto::Ultra));
        assert_eq!(req.recipient_pubkey_path.as_deref(), Some("/home/user/keys/qenc-key.qenc.pub"));
        assert!(req.passphrase.is_none());
    }

    #[test]
    fn deserialize_decrypt_request_passphrase() {
        let payload = json!({
            "input": "/home/user/out.qenc",
            "output": "/home/user/restored",
            "passphrase": "correct horse battery staple"
        });
        let req: DecryptRequestDto = serde_json::from_value(payload).expect("deserialize DecryptRequestDto");
        assert_eq!(req.input, "/home/user/out.qenc");
        assert_eq!(req.output, "/home/user/restored");
        assert!(req.secret_key_path.is_none());
    }

    #[test]
    fn deserialize_decrypt_request_hybrid() {
        let payload = json!({
            "input": "/home/user/out.qenc",
            "output": "/home/user/restored",
            "secretKeyPath": "/home/user/keys/qenc-key.qenc.sec",
            "secretKeyPassphrase": "key pass"
        });
        let req: DecryptRequestDto = serde_json::from_value(payload).expect("deserialize DecryptRequestDto");
        assert_eq!(req.secret_key_path.as_deref(), Some("/home/user/keys/qenc-key.qenc.sec"));
        assert_eq!(req.secret_key_passphrase.as_deref(), Some("key pass"));
    }

    #[test]
    fn deserialize_keygen_request() {
        let payload = json!({
            "outputDir": "/home/user/keys",
            "namePrefix": "qenc-key",
            "passphrase": "vault pass"
        });
        let req: KeygenRequestDto = serde_json::from_value(payload).expect("deserialize KeygenRequestDto");
        assert_eq!(req.output_dir, "/home/user/keys");
        assert_eq!(req.name_prefix, "qenc-key");
        assert_eq!(req.passphrase.as_deref(), Some("vault pass"));
    }

    #[test]
    fn deserialize_inspect_input_paths() {
        // invoke('inspect_input_paths', { paths }) -> Vec<String>
        let payload = json!({ "paths": ["/a/b", "/c"] });
        let paths: Vec<String> = serde_json::from_value(payload.get("paths").cloned().unwrap()).unwrap();
        assert_eq!(paths, vec!["/a/b".to_string(), "/c".to_string()]);
    }

    // ---- 2. Serialize responses, assert EXACT camelCase keys main.ts reads ----

    #[test]
    fn serialize_operation_summary_camel_case() {
        let dto = OperationSummaryDto {
            output_size: 12_345,
            compression_ratio_percent: 87.5,
            elapsed_ms: 1_234,
            avg_mb_per_sec: 42.0,
            output_path: "/home/user/archive.qenc".into(),
        };
        let v = serde_json::to_value(&dto).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("outputSize"), "keys: {obj:?}");
        assert!(obj.contains_key("compressionRatioPercent"));
        assert!(obj.contains_key("elapsedMs"));
        assert!(obj.contains_key("avgMbPerSec"));
        assert!(!obj.contains_key("output_size"));
        assert!(!obj.contains_key("elapsed_ms"));
    }

    #[test]
    fn serialize_keygen_summary_camel_case() {
        let dto = KeygenSummaryDto {
            public_key_path: "/k/x.qenc.pub".into(),
            secret_key_path: "/k/x.qenc.sec".into(),
            fingerprint: "abcd".into(),
        };
        let v = serde_json::to_value(&dto).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("publicKeyPath"));
        assert!(obj.contains_key("secretKeyPath"));
        assert!(obj.contains_key("fingerprint"));
    }

    #[test]
    fn serialize_input_path_info_camel_case() {
        let dto = InputPathInfoDto {
            path: "/a/b".into(),
            name: "b".into(),
            size_bytes: 2048,
            is_dir: true,
            file_count: 3,
        };
        let v = serde_json::to_value(&dto).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("sizeBytes"));
        assert!(obj.contains_key("isDir"));
        assert!(obj.contains_key("fileCount"));
        assert!(!obj.contains_key("size_bytes"));
        assert!(!obj.contains_key("is_dir"));
    }

    #[test]
    fn serialize_system_info_camel_case() {
        let dto = SystemInfoDto {
            platform: "linux".into(),
            is_mobile: false,
            recommended_argon2_profile: "desktop".into(),
            engine_version: "QENC v1".into(),
        };
        let v = serde_json::to_value(&dto).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("recommendedArgon2Profile"));
        assert!(obj.contains_key("engineVersion"));
    }

    #[test]
    fn serialize_progress_event_camel_case_and_enum_strings() {
        let dto = ProgressEventDto {
            stage: "Encrypting".into(),
            percent: 42.5,
            bytes_processed: 100,
            total_bytes: Some(200),
            output_bytes: 50,
            elapsed_ms: 10,
            mb_per_sec: 5.0,
        };
        let v = serde_json::to_value(&dto).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("stage"));
        assert!(obj.contains_key("percent"));
        assert!(obj.contains_key("bytesProcessed"));
        assert!(obj.contains_key("totalBytes"));
        assert!(obj.contains_key("outputBytes"));
        assert!(obj.contains_key("elapsedMs"));
        assert!(obj.contains_key("mbPerSec"));
        assert!(!obj.contains_key("bytes_processed"));
        assert!(!obj.contains_key("total_bytes"));
        assert!(!obj.contains_key("elapsed_ms"));
        assert_eq!(obj.get("percent").unwrap(), &serde_json::json!(42.5));
    }

    #[test]
    fn serialize_inspect_response_camel_case_and_enum_strings() {
        let meta = QencMetadataDto {
            version: 1,
            key_mode: KeyModeDto::Passphrase,
            compression_profile: CompressionProfileDto::Balanced,
            chunk_size: 1_048_576,
            original_size: 4096,
            argon2_params: Some(Argon2ParamsDto { m_cost_kib: 131_072, t_cost: 3, p_cost: 2 }),
            ephemeral_x25519_pk: None,
            mlkem_ciphertext: None,
        };
        let resp = InspectResponseDto { metadata: meta, file_size: 5000 };
        let v = serde_json::to_value(&resp).unwrap();
        let meta_obj = v.get("metadata").unwrap().as_object().unwrap();
        assert!(meta_obj.contains_key("keyMode"));
        assert!(meta_obj.contains_key("compressionProfile"));
        assert!(meta_obj.contains_key("chunkSize"));
        assert!(meta_obj.contains_key("originalSize"));
        assert!(meta_obj.contains_key("argon2Params"));
        assert!(v.as_object().unwrap().contains_key("fileSize"));
        // Enum string values must be camelCase tokens main.ts compares against
        assert_eq!(meta_obj.get("keyMode").unwrap(), "passphrase");
        assert_eq!(meta_obj.get("compressionProfile").unwrap(), "balanced");
        // nested Argon2 params
        let argon = meta_obj.get("argon2Params").unwrap().as_object().unwrap();
        assert!(argon.contains_key("mCostKib"));
        assert!(argon.contains_key("tCost"));
        assert!(argon.contains_key("pCost"));
    }

    #[test]
    fn key_mode_enum_round_trips_exact_strings() {
        // "passphrase" | "hybridPqc" are the ONLY accepted JSON strings.
        assert!(serde_json::from_value::<KeyModeDto>(json!("passphrase")).is_ok());
        assert!(serde_json::from_value::<KeyModeDto>(json!("hybridPqc")).is_ok());
        assert!(serde_json::from_value::<KeyModeDto>(json!("Passphrase")).is_err());
        assert!(serde_json::from_value::<KeyModeDto>(json!("hybrid")).is_err());
        assert_eq!(serde_json::to_value(&KeyModeDto::Passphrase).unwrap(), json!("passphrase"));
        assert_eq!(serde_json::to_value(&KeyModeDto::HybridPqc).unwrap(), json!("hybridPqc"));
    }

    #[test]
    fn compression_profile_enum_round_trips_exact_strings() {
        assert_eq!(serde_json::to_value(&CompressionProfileDto::Turbo).unwrap(), json!("turbo"));
        assert_eq!(serde_json::to_value(&CompressionProfileDto::Balanced).unwrap(), json!("balanced"));
        assert_eq!(serde_json::to_value(&CompressionProfileDto::Ultra).unwrap(), json!("ultra"));
        assert!(serde_json::from_value::<CompressionProfileDto>(json!("Turbo")).is_err());
    }

    #[test]
    fn extract_display_name_android_saf_uri() {
        assert_eq!(
            super::extract_display_name(
                "content://com.android.externalstorage.documents/document/primary%3ADownload%2Freport%20final.pdf",
                0
            ),
            "report final.pdf"
        );
    }

    #[test]
    fn extract_display_name_opaque_document_id() {
        // Opaque media document id -> decodes to a reasonable label (no path sep).
        assert_eq!(
            super::extract_display_name("content://media/external/images/media/12345", 7),
            "12345"
        );
    }

    #[test]
    fn extract_display_name_regular_paths() {
        assert_eq!(super::extract_display_name("/home/user/notes/backup.qenc", 0), "backup.qenc");
        assert_eq!(super::extract_display_name("C:\\Users\\me\\a\\file.txt", 0), "file.txt");
        // Traversal-only segment -> safe fallback.
        assert_eq!(super::extract_display_name("content://x/..", 3), "input_3");
    }

    #[test]
    fn is_content_or_file_uri_detects_uris() {
        assert!(super::is_content_or_file_uri("content://foo/bar"));
        assert!(super::is_content_or_file_uri("FILE://foo/bar"));
        assert!(super::is_content_or_file_uri("file:///a/b"));
        assert!(!super::is_content_or_file_uri("/home/user/a.qenc"));
        assert!(!super::is_content_or_file_uri("./relative.qenc"));
    }

    #[test]
    fn default_paths_response_camel_case() {
        let v = serde_json::to_value(&DefaultPathsResponse {
            encrypted_dir: "/data/qenc/encrypted".into(),
            decrypted_dir: "/data/qenc/decrypted".into(),
            keys_dir: "/data/qenc/keys".into(),
        })
        .unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("encryptedDir"));
        assert!(obj.contains_key("decryptedDir"));
        assert!(obj.contains_key("keysDir"));
    }

    #[test]
    fn system_info_serializes_is_mobile_camel_case() {
        let v = serde_json::to_value(&SystemInfoDto {
            platform: "android".into(),
            is_mobile: true,
            recommended_argon2_profile: "mobile".into(),
            engine_version: "QENC v1".into(),
        })
        .unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("isMobile"));
        assert_eq!(obj.get("isMobile").unwrap(), &json!(true));
        assert_eq!(obj.get("recommendedArgon2Profile").unwrap(), &json!("mobile"));
    }
}

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use sha2::{Sha256, Digest};

    /// Build a realistic nested tree: 0-byte file, binary file, >250-char nested
    /// path, and a valid internal relative symlink.
    fn build_tree(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
        // 0-byte file
        let empty = root.join("empty.bin");
        fs::write(&empty, b"").unwrap();

        // Binary file with deterministic content
        let binary = root.join("binary.bin");
        let mut bin_bytes = vec![0u8; 4096];
        for (i, b) in bin_bytes.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        fs::write(&binary, &bin_bytes).unwrap();

        // > 250-char nested directory path
        let mut deep = root.join("project");
        fs::create_dir_all(&deep).unwrap();
        for i in 0..6 {
            deep = deep.join(format!("deeply_nested_directory_segment_number_{i}_padding_padding_padding"));
        }
        fs::create_dir_all(&deep).unwrap();
        let deep_file = deep.join("buried_payload.dat");
        fs::write(&deep_file, b"deep content").unwrap();
        assert!(deep_file.to_string_lossy().len() > 250);

        // Valid internal relative symlink: node_modules/.bin/tool -> ../lib/tool.js
        let nm = root.join("project/node_modules/.bin");
        fs::create_dir_all(&nm).unwrap();
        fs::create_dir_all(root.join("project/node_modules/lib")).unwrap();
        fs::write(root.join("project/node_modules/lib/tool.js"), b"console.log('hi')").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("../lib/tool.js", nm.join("tool")).unwrap();

        (empty, binary, deep_file)
    }

    fn sha256_file(path: &Path) -> Vec<u8> {
        let mut hasher = Sha256::new();
        let data = fs::read(path).unwrap();
        hasher.update(&data);
        hasher.finalize().to_vec()
    }

    fn do_encrypt(inputs: &[PathBuf], output: &Path, opts: EncryptOptions) -> qenc_core::Result<u64> {
        let writer = std::fs::File::create(output)?;
        let buf = std::io::BufWriter::new(writer);
        qenc_core::encrypt_stream(inputs, buf, opts)?;
        Ok(std::fs::metadata(output)?.len())
    }

    #[test]
    fn e2e_passphrase_encrypt_inspect_decrypt_sha256_match() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        let (empty, binary, deep_file) = build_tree(&src);

        let out = tmp.path().join("archive.qenc");
        let opts = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some("strong test passphrase".into()),
            ..Default::default()
        };
        let written = do_encrypt(std::slice::from_ref(&src), &out, opts).unwrap();
        assert!(written > 0);

        // Inspect (the exact call inspect_container makes)
        let meta = {
            let mut f = fs::File::open(&out).unwrap();
            qenc_core::inspect_header(&mut f).unwrap()
        };
        assert_eq!(meta.version, 1);
        assert_eq!(meta.key_mode, KeyMode::Passphrase);
        assert!(meta.argon2_params.is_some());

        // Decrypt (the exact call decrypt_container makes)
        let restored = tmp.path().join("restored");
        let dopts = DecryptOptions {
            passphrase: Some("strong test passphrase".into()),
            ..Default::default()
        };
        let reader = fs::File::open(&out).unwrap();
        qenc_core::decrypt_stream(std::io::BufReader::new(reader), &restored, dopts).unwrap();

        // SHA-256 exact match for every payload file.
        // The archive stores the selected folder name as the top-level dir ("src/...").
        let base = restored.join("src");
        assert_eq!(sha256_file(&base.join("empty.bin")), sha256_file(&empty));
        assert_eq!(sha256_file(&base.join("binary.bin")), sha256_file(&binary));
        let restored_deep = base.join(deep_file.strip_prefix(&src).unwrap());
        assert_eq!(sha256_file(&restored_deep), sha256_file(&deep_file));
    }

    #[test]
    fn e2e_hybrid_pqc_encrypt_inspect_decrypt_sha256_match() {
        use qenc_core::crypto::{
            generate_full_hybrid_keypair, save_public_key, save_full_secret_key,
        };

        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        let (_empty, binary, deep_file) = build_tree(&src);

        // Generate real Hybrid keypair (full ML-KEM-1024 decaps key)
        let (public, secret) = generate_full_hybrid_keypair().unwrap();
        let pub_path = tmp.path().join("id.qenc.pub");
        let sec_path = tmp.path().join("id.qenc.sec");
        save_public_key(&pub_path, &public).unwrap();
        save_full_secret_key(&sec_path, &secret, None).unwrap();

        let out = tmp.path().join("archive.qenc");
        let opts = EncryptOptions {
            mode: KeyMode::HybridPqc,
            profile: CompressionProfile::Ultra,
            passphrase: None,
            recipient_pubkey_path: Some(pub_path.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let written = do_encrypt(std::slice::from_ref(&src), &out, opts).unwrap();
        assert!(written > 0);

        // Inspect
        let meta = {
            let mut f = fs::File::open(&out).unwrap();
            qenc_core::inspect_header(&mut f).unwrap()
        };
        assert_eq!(meta.key_mode, KeyMode::HybridPqc);
        assert!(meta.ephemeral_x25519_pk.is_some());
        assert!(meta.mlkem_ciphertext.is_some());

        // Decrypt with secret key
        let restored = tmp.path().join("restored");
        let dopts = DecryptOptions {
            passphrase: None,
            secret_key_path: Some(sec_path.to_string_lossy().into_owned()),
            secret_key_passphrase: None,
            ..Default::default()
        };
        let reader = fs::File::open(&out).unwrap();
        qenc_core::decrypt_stream(std::io::BufReader::new(reader), &restored, dopts).unwrap();

        // Archive stores the folder name as top-level dir ("src/...").
        let base = restored.join("src");
        assert_eq!(sha256_file(&base.join("binary.bin")), sha256_file(&binary));
        let restored_deep = base.join(deep_file.strip_prefix(&src).unwrap());
        assert_eq!(sha256_file(&restored_deep), sha256_file(&deep_file));
    }

    #[test]
    fn e2e_wrong_passphrase_fails_and_no_false_success() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("secret.txt"), b"top secret").unwrap();

        let out = tmp.path().join("archive.qenc");
        let opts = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Turbo,
            passphrase: Some("right".into()),
            ..Default::default()
        };
        do_encrypt(std::slice::from_ref(&src), &out, opts).unwrap();

        let restored = tmp.path().join("restored");
        let dopts = DecryptOptions {
            passphrase: Some("wrong".into()),
            ..Default::default()
        };
        let reader = fs::File::open(&out).unwrap();
        let res = qenc_core::decrypt_stream(std::io::BufReader::new(reader), &restored, dopts);
        assert!(res.is_err(), "decryption with wrong passphrase must fail");
    }
}
