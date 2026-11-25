//! Safe streaming TAR packer and path-traversal-proof unpacker.

use std::fs::{File, DirBuilder, Metadata, read_dir};
use std::io::{Read, Write};
use std::path::{Path, Component};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::AtomicU64;
use tar::{Builder, Archive, EntryType, Header};
use walkdir::WalkDir;
use crate::{Result, QencError, NamedStreamInput};

/// Maximum path length for safety (we allow very long paths via GNU extensions)
const MAX_PATH_LEN: usize = 4096;

/// A `Read` wrapper that counts the number of raw bytes passing through it.
struct CountingReader<'a, R: Read> {
    inner: R,
    count: &'a AtomicU64,
}

impl<R: Read> Read for CountingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(n)
    }
}

/// Optional progress instrumentation threaded through TAR packing.
///
/// `counter` accumulates the raw bytes read from source files; `on_file` is
/// invoked after each top-level file is packed so callers can emit progress.
pub struct PackProgress<'a> {
    pub counter: Option<&'a AtomicU64>,
    pub on_file: Option<&'a mut dyn FnMut()>,
}

impl PackProgress<'_> {
    #[must_use]
    pub fn none() -> Self {
        Self { counter: None, on_file: None }
    }
}

/// Creates a streaming TAR archive from a list of input paths.
///
/// The output is written to the provided writer. This function streams
/// the archive without loading everything into memory.
/// Uses GNU LongName/LongLink extensions for paths > 100 bytes.
pub fn create_tar_stream<W: Write + Send>(inputs: &[impl AsRef<Path>], writer: W) -> Result<()> {
    let mut pp = PackProgress::none();
    create_tar_stream_inner(inputs, writer, &mut pp)
}

/// Creates a streaming TAR archive while counting raw input bytes and invoking
/// `on_file` after each file is packed (for live progress reporting).
pub fn create_tar_stream_counted<W: Write + Send>(
    inputs: &[impl AsRef<Path>],
    writer: W,
    counter: &AtomicU64,
    mut on_file: impl FnMut(),
) -> Result<()> {
    let mut pp = PackProgress { counter: Some(counter), on_file: Some(&mut on_file) };
    create_tar_stream_inner(inputs, writer, &mut pp)
}

fn create_tar_stream_inner<W: Write + Send>(
    inputs: &[impl AsRef<Path>],
    writer: W,
    pp: &mut PackProgress<'_>,
) -> Result<()> {
    let mut builder = Builder::new(writer);
    builder.follow_symlinks(false); // Never follow symlinks for security

    for input in inputs {
        let path = input.as_ref();
        add_to_tar(&mut builder, path, path, pp)?;
    }

    builder.finish()?;
    Ok(())
}

/// Sanitizes + de-duplicates a stream name into a safe archive basename.
///
/// - Strips any directory prefix (keeps only the final component).
/// - Rejects empty, `.` and `..` (traversal) names.
/// - De-duplicates collisions like `file (1).ext`.
fn sanitize_and_dedupe_name(name: &str, used: &mut std::collections::HashSet<String>) -> Result<String> {
    // Keep only the final path component (handle both separators).
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();

    if base.is_empty() || base == "." || base == ".." || base.contains('\0') {
        return Err(QencError::Archive(format!("Invalid stream name: {name:?}")));
    }

    if !used.contains(base) {
        used.insert(base.to_string());
        return Ok(base.to_string());
    }

    // Split off the extension for a `name (n).ext` style duplicate.
    let (stem, ext) = match base.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() && !e.is_empty() => (s, Some(e)),
        _ => (base, None),
    };

    let mut i = 1u32;
    loop {
        let candidate = match ext {
            Some(e) => format!("{stem} ({i}).{e}"),
            None => format!("{stem} ({i})"),
        };
        if !used.contains(&candidate) {
            used.insert(candidate.clone());
            return Ok(candidate);
        }
        i += 1;
        if i > 100_000 {
            return Err(QencError::Archive("Too many duplicate stream names".into()));
        }
    }
}

/// Packs named byte streams into a streaming GNU TAR archive.
///
/// Counts raw input bytes into `raw_counter` and invokes `on_entry` after each
/// stream for live progress. Handles Android SAF readers without temp copies.
pub fn pack_named_entries_to_tar<W: Write + Send>(
    entries: Vec<NamedStreamInput>,
    writer: W,
    raw_counter: &AtomicU64,
    mut on_entry: impl FnMut(),
) -> Result<()> {
    let mut builder = Builder::new(writer);
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();

    for entry in entries {
        let safe_name = sanitize_and_dedupe_name(&entry.name, &mut used)?;
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_size(entry.size);
        header.set_mode(0o644);
        header.set_cksum();

        let mut counting = CountingReader { inner: entry.reader, count: raw_counter };
        builder.append_data(&mut header, safe_name.as_str(), &mut counting)
            .map_err(|e| QencError::Archive(format!("Failed to add {safe_name} to tar: {e}")))?;

        on_entry();
    }

    builder.finish()?;
    Ok(())
}

/// Adds a file or directory to the TAR archive recursively.
fn add_to_tar<W: Write>(builder: &mut Builder<W>, root: &Path, path: &Path, pp: &mut PackProgress<'_>) -> Result<()> {
    let metadata = path.symlink_metadata()
        .map_err(|e| QencError::Archive(format!("Failed to read metadata for {}: {}", path.display(), e)))?;

    let rel_path = path.strip_prefix(root)
        .map_err(|_| QencError::Archive(format!("Path {} not under root {}", path.display(), root.display())))?;

    // If rel_path is empty (single file input), use the file name
    let archive_path: &Path = if rel_path.as_os_str().is_empty() {
        Path::new(path.file_name().ok_or_else(|| QencError::Archive("Invalid input path: no file name".into()))?)
    } else {
        rel_path
    };

    // Skip if path is too long
    let path_str = archive_path.to_string_lossy();
    if path_str.len() > MAX_PATH_LEN {
        return Err(QencError::Archive(format!("Path too long: {path_str}")));
    }

    if metadata.is_file() {
        add_file_to_tar(builder, path, archive_path, &metadata, pp)?;
    } else if metadata.is_dir() {
        add_dir_to_tar(builder, root, path, archive_path, pp)?;
    } else if metadata.file_type().is_symlink() {
        // Store symlinks as regular entries with symlink type
        add_symlink_to_tar(builder, path, archive_path)?;
    }
    // Skip other file types (devices, pipes, sockets) for security

    Ok(())
}

/// Seconds since the Unix epoch for a file's modification time.
///
/// Uses `Metadata::modified()` on every platform (Linux, Windows, Android) so
/// timestamp handling is identical everywhere. Pre-epoch or unavailable
/// timestamps degrade to `0` instead of wrapping to a huge value.
fn mtime_secs(metadata: &Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

/// Resolves the `(mode, mtime, uid, gid)` tuple for a TAR header, cross-platform.
///
/// On Unix the real POSIX mode bits / owner are preserved from the filesystem.
/// On Windows and Android (`std::os::unix::fs::MetadataExt` is unavailable) we
/// record deterministic, POSIX-friendly defaults: `0o755` for directories,
/// `0o644` for regular files, `uid = gid = 0`. `mtime` always comes from
/// [`mtime_secs`] so archives stay portable between all three platforms.
fn header_mode_mtime_owner(is_dir: bool, metadata: &Metadata) -> (u32, u64, u64, u64) {
    #[cfg(unix)]
    {
        let _ = is_dir;
        (
            metadata.mode() & 0o777,
            mtime_secs(metadata),
            u64::from(metadata.uid()),
            u64::from(metadata.gid()),
        )
    }
    #[cfg(not(unix))]
    {
        let mode = if is_dir { 0o755 } else { 0o644 };
        (mode, mtime_secs(metadata), 0, 0)
    }
}

/// Adds a regular file to the TAR archive using `append_data` which
/// automatically handles GNU `LongName` extensions for paths > 100 bytes.
fn add_file_to_tar<W: Write>(builder: &mut Builder<W>, path: &Path, rel_path: &Path, metadata: &Metadata, pp: &mut PackProgress<'_>) -> Result<()> {
    let file = File::open(path)
        .map_err(|e| QencError::Archive(format!("Failed to open {}: {}", path.display(), e)))?;

    let (mode, mtime, uid, gid) = header_mode_mtime_owner(false, metadata);

    let mut header = Header::new_gnu();
    header.set_size(metadata.len());
    header.set_mode(mode);
    header.set_mtime(mtime);
    header.set_uid(uid);
    header.set_gid(gid);
    header.set_cksum();

    // Wrap in a counting reader so raw input bytes are tracked for progress.
    let append_res = if let Some(counter) = pp.counter {
        let mut counting = CountingReader { inner: file, count: counter };
        builder.append_data(&mut header, rel_path, &mut counting)
    } else {
        let mut file = file;
        builder.append_data(&mut header, rel_path, &mut file)
    }
    .map_err(|e| QencError::Archive(format!("Failed to add {} to tar: {}", path.display(), e)));

    append_res?;
    if let Some(cb) = pp.on_file.as_mut() {
        cb();
    }
    Ok(())
}

/// Adds a directory to the TAR archive recursively.
fn add_dir_to_tar<W: Write>(builder: &mut Builder<W>, root: &Path, path: &Path, rel_path: &Path, pp: &mut PackProgress<'_>) -> Result<()> {
    // Add directory entry using append_data with empty reader
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Directory);
    header.set_mode(0o755);
    header.set_size(0); // Directories must have size 0
    header.set_cksum();

    // Use append_data with empty reader which handles GNU LongName for long paths
    builder.append_data(&mut header, rel_path, std::io::empty())
        .map_err(|e| QencError::Archive(format!("Failed to add directory {} to tar: {}", rel_path.display(), e)))?;

    // Recurse into directory
    let entries = read_dir(path)
        .map_err(|e| QencError::Archive(format!("Failed to read directory {}: {}", path.display(), e)))?;

    for entry in entries {
        let entry = entry.map_err(|e| QencError::Archive(format!("Failed to read dir entry: {e}")))?;
        let entry_path = entry.path();
        // For children, the relative path is rel_path joined with the child's file name
        let child_rel_path = rel_path.join(entry.file_name());
        add_to_tar_with_rel_path(builder, root, &entry_path, &child_rel_path, pp)?;
    }

    Ok(())
}

/// Adds a file or directory to the TAR archive with a pre-computed relative path.
fn add_to_tar_with_rel_path<W: Write>(builder: &mut Builder<W>, root: &Path, path: &Path, rel_path: &Path, pp: &mut PackProgress<'_>) -> Result<()> {
    let metadata = path.symlink_metadata()
        .map_err(|e| QencError::Archive(format!("Failed to read metadata for {}: {}", path.display(), e)))?;

    // Skip if path is too long
    let path_str = rel_path.to_string_lossy();
    if path_str.len() > MAX_PATH_LEN {
        return Err(QencError::Archive(format!("Path too long: {path_str}")));
    }

    if metadata.is_file() {
        add_file_to_tar(builder, path, rel_path, &metadata, pp)?;
    } else if metadata.is_dir() {
        add_dir_to_tar(builder, root, path, rel_path, pp)?;
    } else if metadata.file_type().is_symlink() {
        // Store symlinks as regular entries with symlink type
        add_symlink_to_tar(builder, path, rel_path)?;
    }
    // Skip other file types (devices, pipes, sockets) for security

    Ok(())
}

/// Adds a symlink to the TAR archive using `append_link` which
/// automatically handles GNU `LongLink` extensions for long link targets.
fn add_symlink_to_tar<W: Write>(builder: &mut Builder<W>, path: &Path, rel_path: &Path) -> Result<()> {
    let target = std::fs::read_link(path)
        .map_err(|e| QencError::Archive(format!("Failed to read symlink {}: {}", path.display(), e)))?;

    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Symlink);
    header.set_mode(0o777);
    header.set_size(0); // Symlinks have no data
    header.set_cksum();

    // Use `append_link` which automatically handles GNU `LongLink` for long link targets
    builder.append_link(&mut header, rel_path, &target)
        .map_err(|e| QencError::Archive(format!("Failed to add symlink {} to tar: {}", rel_path.display(), e)))?;

    Ok(())
}

/// Windows fallback used when the OS refuses to create a symlink
/// (`SeCreateSymbolicLinkPrivilege` missing / Developer Mode disabled).
///
/// Copies the link target's contents when it is a regular file so the extracted
/// payload is still usable. Returns `false` when nothing could be materialized
/// (missing or non-regular target), letting the caller skip the entry safely.
#[cfg(windows)]
fn materialize_symlink_target(link_canonical: &Path, target_path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(link_canonical) {
        Ok(meta) if meta.is_file() => {
            std::fs::copy(link_canonical, target_path).map_err(QencError::Io)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Safely extracts a TAR archive to a destination directory.
///
/// This function validates every entry path to prevent path traversal attacks.
/// It rejects:
/// - Absolute paths
/// - Paths containing `..` components
/// - Symlinks/hardlinks pointing outside the destination root
/// - Device nodes, FIFOs, sockets
pub fn extract_tar_stream<R: Read + Send>(reader: R, dest_dir: &Path) -> Result<()> {
    // Ensure destination directory exists
    DirBuilder::new().recursive(true).create(dest_dir)
        .map_err(QencError::Io)?;

    // Canonicalize destination for path traversal checks
    let dest_canonical = dest_dir.canonicalize()
        .map_err(QencError::Io)?;

    let mut archive = Archive::new(reader);
    archive.set_unpack_xattrs(false); // Don't restore extended attributes
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);

    // Get entries iterator, converting tar crate's path traversal errors to our error type
    let entries = archive.entries().map_err(|e| {
        let err_str = e.to_string();
        if err_str.contains("must not have `..`") || err_str.contains("must be relative") || err_str.contains("absolute") {
            QencError::PathTraversal(err_str)
        } else {
            QencError::Archive(err_str)
        }
    })?;

    for entry_result in entries {
        let mut entry = entry_result.map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("must not have `..`") || err_str.contains("must be relative") || err_str.contains("absolute") {
                QencError::PathTraversal(err_str)
            } else {
                QencError::Archive(err_str)
            }
        })?;

        // Get the entry path (clone to avoid borrow issues)
        let path = entry.path()
            .map_err(|e| QencError::Archive(e.to_string()))?
            .to_path_buf();

        // Validate path for traversal (our additional check)
        validate_entry_path(&path)?;

        // Construct the target path
        let target_path = dest_canonical.join(&path);

        // Additional safety: ensure target is within destination
        if !target_path.starts_with(&dest_canonical) {
            return Err(QencError::PathTraversal(format!(
                "Entry path {} escapes destination directory", path.display()
            )));
        }

        // Handle different entry types safely
        let header = entry.header();
        let entry_type = header.entry_type();

        match entry_type {
            EntryType::Regular | EntryType::Continuous => {
                // Regular file - extract normally
                let parent = target_path.parent().ok_or_else(|| {
                    QencError::Archive("Failed to get parent directory of target path".into())
                })?;
                DirBuilder::new().recursive(true).create(parent)
                    .map_err(QencError::Io)?;

                entry.unpack(&target_path)
                    .map_err(|e| QencError::Archive(format!("Failed to extract {}: {}", path.display(), e)))?;
            }
            EntryType::Directory => {
                // Directory - create it
                DirBuilder::new().recursive(true).create(&target_path)
                    .map_err(QencError::Io)?;
            }
            EntryType::Symlink => {
                // Symlink - validate target doesn't escape
                let link_target = header.link_name()
                    .map_err(|e| QencError::Archive(e.to_string()))?
                    .ok_or_else(|| QencError::Archive("Symlink missing target".into()))?;
                // Normalize `Cow<'_, Path>` -> `&Path` up front: this keeps the
                // `AsRef<Path>` bounds of `symlink{,_dir,_file}` satisfied on
                // every platform (no reliance on blanket impls for `&Cow<Path>`).
                let link_target: &Path = &link_target;

                // Resolve the symlink target relative to the target directory
                let link_path = target_path.parent().ok_or_else(|| {
                    QencError::Archive("Failed to get parent directory of target path".into())
                })?.join(link_target);
                let link_canonical = link_path.canonicalize()
                    .unwrap_or(link_path); // If target doesn't exist yet, use as-is

                // Check if resolved symlink target is within destination
                if !link_canonical.starts_with(&dest_canonical) {
                    return Err(QencError::PathTraversal(format!(
                        "Symlink {} points outside destination: {}", path.display(), link_target.display()
                    )));
                }

                // Create parent directory if needed
                let parent = target_path.parent().ok_or_else(|| {
                    QencError::Archive("Failed to get parent directory of target path".into())
                })?;
                DirBuilder::new().recursive(true).create(parent)
                    .map_err(QencError::Io)?;

                // Create the symlink
                #[cfg(unix)]
                {
                    std::os::unix::fs::symlink(link_target, &target_path)
                        .map_err(QencError::Io)?;
                }
                #[cfg(windows)]
                {
                    // Creating a symlink on Windows needs SeCreateSymbolicLinkPrivilege
                    // (Developer Mode or an elevated process). Handle denial gracefully:
                    // materialize the target file's contents when it is a regular file,
                    // otherwise skip the entry instead of failing the whole extraction.
                    let created = if link_canonical.is_dir() {
                        std::os::windows::fs::symlink_dir(&link_target, &target_path)
                    } else {
                        std::os::windows::fs::symlink_file(&link_target, &target_path)
                    };
                    match created {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                            if !materialize_symlink_target(&link_canonical, &target_path)? {
                                continue;
                            }
                        }
                        Err(e) => return Err(QencError::Io(e)),
                    }
                }
            }
            EntryType::Link => {
                // Hard link - validate target is within destination
                let link_target = header.link_name()
                    .map_err(|e| QencError::Archive(e.to_string()))?
                    .ok_or_else(|| QencError::Archive("Hard link missing target".into()))?;
                // Normalize `Cow<'_, Path>` -> `&Path` (see the symlink arm above).
                let link_target: &Path = &link_target;

                let link_path = dest_canonical.join(link_target);
                if !link_path.starts_with(&dest_canonical) {
                    return Err(QencError::PathTraversal(format!(
                        "Hard link {} points outside destination", path.display()
                    )));
                }

                let parent = target_path.parent().ok_or_else(|| {
                    QencError::Archive("Failed to get parent directory of target path".into())
                })?;
                DirBuilder::new().recursive(true).create(parent)
                    .map_err(QencError::Io)?;

                std::fs::hard_link(&link_path, &target_path)
                    .map_err(QencError::Io)?;
            }
            EntryType::Block | EntryType::Char | EntryType::Fifo => {
                // Reject device nodes and FIFOs for security
                return Err(QencError::Archive(format!(
                    "Unsupported entry type (device/FIFO): {}", path.display()
                )));
            }
            _ => {
                // Unknown entry type - skip with warning or error
                return Err(QencError::Archive(format!(
                    "Unknown entry type for: {}", path.display()
                )));
            }
        }
    }

    Ok(())
}

/// Validates a TAR entry path for safety.
fn validate_entry_path(path: &Path) -> Result<()> {
    let path_str = path.to_string_lossy();

    // Check path length
    if path_str.len() > MAX_PATH_LEN {
        return Err(QencError::PathTraversal(format!("Path too long: {path_str}")));
    }

    // Check for absolute path
    if path.is_absolute() {
        return Err(QencError::PathTraversal(format!("Absolute path not allowed: {path_str}")));
    }

    // Check for path traversal components
    for component in path.components() {
        match component {
            Component::ParentDir => {
                return Err(QencError::PathTraversal(format!("Parent directory traversal not allowed: {path_str}")));
            }
            Component::RootDir => {
                return Err(QencError::PathTraversal(format!("Root directory not allowed: {path_str}")));
            }
            Component::Prefix(_) => {
                return Err(QencError::PathTraversal(format!("Windows prefix not allowed: {path_str}")));
            }
            _ => {}
        }
    }

    // Check for suspicious patterns
    if path_str.contains("..") {
        return Err(QencError::PathTraversal(format!("Path contains '..': {path_str}")));
    }

    Ok(())
}

/// Estimates the uncompressed size of input paths for progress reporting.
pub fn estimate_input_size(inputs: &[impl AsRef<Path>]) -> u64 {
    let mut total = 0u64;

    for input in inputs {
        let path = input.as_ref();
        if let Ok(metadata) = path.metadata() {
            if metadata.is_file() {
                total += metadata.len();
            } else if metadata.is_dir() {
                // Walk directory and sum file sizes
                for entry in WalkDir::new(path).into_iter().filter_map(std::result::Result::ok) {
                    if entry.file_type().is_file() {
                        if let Ok(meta) = entry.metadata() {
                            total += meta.len();
                        }
                    }
                }
            }
        }
    }

    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use std::io::Cursor;

    #[test]
    fn test_tar_roundtrip_single_file() {
        let temp = TempDir::new().unwrap();
        let input_file = temp.path().join("test.txt");
        fs::write(&input_file, b"Hello, TAR!").unwrap();

        // Create tar
        let mut tar_data = Vec::new();
        create_tar_stream(&[&input_file], &mut tar_data).unwrap();

        // Extract to new location
        let dest = TempDir::new().unwrap();
        extract_tar_stream(Cursor::new(tar_data), dest.path()).unwrap();

        // Verify content
        let extracted = dest.path().join("test.txt");
        assert!(extracted.exists());
        assert_eq!(fs::read(extracted).unwrap(), b"Hello, TAR!");
    }

    #[test]
    fn test_tar_roundtrip_directory() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().join("mydir");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("file1.txt"), b"File 1").unwrap();
        fs::write(dir.join("file2.txt"), b"File 2").unwrap();

        let subdir = dir.join("subdir");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("file3.txt"), b"File 3").unwrap();

        // Create tar
        let mut tar_data = Vec::new();
        create_tar_stream(&[&dir], &mut tar_data).unwrap();

        // Extract
        let dest = TempDir::new().unwrap();
        extract_tar_stream(Cursor::new(tar_data), dest.path()).unwrap();

        // Verify
        assert_eq!(fs::read(dest.path().join("mydir/file1.txt")).unwrap(), b"File 1");
        assert_eq!(fs::read(dest.path().join("mydir/file2.txt")).unwrap(), b"File 2");
        assert_eq!(fs::read(dest.path().join("mydir/subdir/file3.txt")).unwrap(), b"File 3");
    }

    // Windows GitHub runners forbid unprivileged symlink creation (ERROR_PRIVILEGE_NOT_HELD,
    // winerror 1314), so this test only runs on Unix.
    #[test]
    #[cfg(unix)]
    fn test_tar_symlink() {
        let temp = TempDir::new().unwrap();
        let target = temp.path().join("target.txt");
        fs::write(&target, b"Target content").unwrap();

        let link = temp.path().join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink("target.txt", &link).unwrap(); // Relative symlink

        let mut tar_data = Vec::new();
        create_tar_stream(&[&link], &mut tar_data).unwrap();

        // Debug: print tar contents
        let mut archive = Archive::new(Cursor::new(&tar_data));
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            println!("Entry: path={:?}, type={:?}, size={}", entry.path().unwrap(), entry.header().entry_type(), entry.header().size().unwrap());
        }

        let dest = TempDir::new().unwrap();
        extract_tar_stream(Cursor::new(tar_data), dest.path()).unwrap();

        let extracted_link = dest.path().join("link.txt");
        // Use symlink_metadata to check for symlinks (exists() follows symlinks and returns false for broken ones)
        let meta = extracted_link.symlink_metadata().unwrap();
        assert!(meta.file_type().is_symlink());
        // On Unix, it should be a symlink
        #[cfg(unix)]
        {
            let meta = fs::read_link(&extracted_link).unwrap();
            assert_eq!(meta, Path::new("target.txt"));
        }
    }

    /// Creates a raw tar header for testing path traversal (bypasses tar crate validation)
    fn create_raw_tar_entry(path: &str, size: u64, data: &[u8]) -> Vec<u8> {
        let mut block = vec![0u8; 512];
        // Name (100 bytes)
        let path_bytes = path.as_bytes();
        block[0..path_bytes.len().min(100)].copy_from_slice(&path_bytes[..path_bytes.len().min(100)]);
        // Mode (8 bytes)
        block[100..108].copy_from_slice(b"0000644 ");
        // UID (8 bytes)
        block[108..116].copy_from_slice(b"0000000 ");
        // GID (8 bytes)
        block[116..124].copy_from_slice(b"0000000 ");
        // Size (12 bytes, octal) - 11 octal digits + null terminator
        let size_oct = format!("{size:011o}");
        block[124..135].copy_from_slice(size_oct.as_bytes());
        block[135] = 0; // null terminator
        // Mtime (12 bytes)
        block[136..147].copy_from_slice(b"00000000000");
        block[147] = 0;
        // Checksum (8 bytes) - placeholder
        block[148..156].copy_from_slice(b"        ");
        // Typeflag (1 byte)
        block[156] = b'0'; // regular file
        // Linkname (100 bytes) - empty
        // Magic (6 bytes)
        block[257..263].copy_from_slice(b"ustar ");
        // Version (2 bytes)
        block[263..265].copy_from_slice(b"00");
        // Uname (32 bytes)
        block[265..297].copy_from_slice(b"user                            ");
        // Gname (32 bytes)
        block[297..329].copy_from_slice(b"group                           ");
        
        // Calculate checksum (treat checksum bytes as spaces for calculation)
        let mut checksum = 0u32;
        for (i, &b) in block.iter().enumerate() {
            if (148..156).contains(&i) {
                checksum += u32::from(b' '); // checksum field treated as spaces
            } else {
                checksum += u32::from(b);
            }
        }
        let checksum_oct = format!("{checksum:06o}");
        block[148..154].copy_from_slice(checksum_oct.as_bytes());
        block[154] = b' ';
        block[155] = b'\0';
        
        let mut result = block;
        // Add data, padded to 512 bytes
        result.extend_from_slice(data);
        let padding = (512 - (data.len() % 512)) % 512;
        result.extend(vec![0u8; padding]);
        result
    }

    #[test]
    fn test_path_traversal_rejection_absolute() {
        let tar_data = create_raw_tar_entry("/etc/passwd", 10, b"malicious");
        let dest = TempDir::new().unwrap();
        let result = extract_tar_stream(Cursor::new(tar_data), dest.path());
        assert!(matches!(result, Err(QencError::PathTraversal(_))));
    }

    #[test]
    fn test_path_traversal_rejection_parent_dir() {
        let tar_data = create_raw_tar_entry("../evil.txt", 10, b"malicious");
        let dest = TempDir::new().unwrap();
        let result = extract_tar_stream(Cursor::new(tar_data), dest.path());
        assert!(matches!(result, Err(QencError::PathTraversal(_))));
    }

    #[test]
    fn test_path_traversal_rejection_nested_parent() {
        let tar_data = create_raw_tar_entry("subdir/../../evil.txt", 10, b"malicious");
        let dest = TempDir::new().unwrap();
        let result = extract_tar_stream(Cursor::new(tar_data), dest.path());
        assert!(matches!(result, Err(QencError::PathTraversal(_))));
    }

    #[test]
    fn test_device_node_rejection() {
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            let mut header = Header::new_gnu();
            header.set_path("device").unwrap();
            // Use Symlink as a special file type that should be rejected
            header.set_entry_type(EntryType::Symlink);
            header.set_size(0);
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
            builder.finish().unwrap();
        }

        let dest = TempDir::new().unwrap();
        let result = extract_tar_stream(Cursor::new(tar_data), dest.path());
        assert!(matches!(result, Err(QencError::Archive(_))));
    }

    #[test]
    fn test_fifo_rejection() {
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            let mut header = Header::new_gnu();
            header.set_path("fifo").unwrap();
            header.set_entry_type(EntryType::Fifo);
            header.set_size(0);
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
            builder.finish().unwrap();
        }

        let dest = TempDir::new().unwrap();
        let result = extract_tar_stream(Cursor::new(tar_data), dest.path());
        assert!(matches!(result, Err(QencError::Archive(_))));
    }

    #[test]
    fn test_symlink_outside_destination_rejection() {
        let _temp = TempDir::new().unwrap();
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            let mut header = Header::new_gnu();
            header.set_path("link.txt").unwrap();
            header.set_entry_type(EntryType::Symlink);
            header.set_link_name("/etc/passwd").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
            builder.finish().unwrap();
        }

        let dest = TempDir::new().unwrap();
        let result = extract_tar_stream(Cursor::new(tar_data), dest.path());
        assert!(matches!(result, Err(QencError::PathTraversal(_))));
    }

    #[test]
    fn test_estimate_input_size() {
        let temp = TempDir::new().unwrap();
        let file1 = temp.path().join("file1.txt");
        let file2 = temp.path().join("file2.txt");
        fs::write(&file1, b"Hello").unwrap(); // 5 bytes
        fs::write(&file2, b"World!").unwrap(); // 6 bytes

        let size = estimate_input_size(&[&file1, &file2]);
        assert_eq!(size, 11);
    }

    // New tests for long path support
    #[test]
    fn test_long_file_path() {
        let temp = TempDir::new().unwrap();
        // Create a deeply nested directory with a very long path (> 255 chars)
        let mut long_path = temp.path().to_path_buf();
        for i in 0..10 {
            long_path = long_path.join(format!("very_long_directory_name_{i}_that_exceeds_normal_limits"));
            fs::create_dir_all(&long_path).unwrap();
        }
        let long_file = long_path.join("very_long_file_name_that_exceeds_the_traditional_tar_limit_of_100_bytes.txt");
        fs::write(&long_file, b"Long path test content").unwrap();

        // Verify path length exceeds 255 chars
        assert!(long_file.to_string_lossy().len() > 255);

        // Create tar - should handle long paths via GNU extensions
        // Pass the top-level temp directory to preserve the full relative path
        let mut tar_data = Vec::new();
        create_tar_stream(&[&temp.path().join("very_long_directory_name_0_that_exceeds_normal_limits")], &mut tar_data).unwrap();

        // Extract
        let dest = TempDir::new().unwrap();
        extract_tar_stream(Cursor::new(tar_data), dest.path()).unwrap();

        // Verify content
        let extracted = dest.path().join("very_long_directory_name_0_that_exceeds_normal_limits")
            .join("very_long_directory_name_1_that_exceeds_normal_limits")
            .join("very_long_directory_name_2_that_exceeds_normal_limits")
            .join("very_long_directory_name_3_that_exceeds_normal_limits")
            .join("very_long_directory_name_4_that_exceeds_normal_limits")
            .join("very_long_directory_name_5_that_exceeds_normal_limits")
            .join("very_long_directory_name_6_that_exceeds_normal_limits")
            .join("very_long_directory_name_7_that_exceeds_normal_limits")
            .join("very_long_directory_name_8_that_exceeds_normal_limits")
            .join("very_long_directory_name_9_that_exceeds_normal_limits")
            .join("very_long_file_name_that_exceeds_the_traditional_tar_limit_of_100_bytes.txt");
        assert!(extracted.exists());
        assert_eq!(fs::read(extracted).unwrap(), b"Long path test content");
    }

    // Symlinks cannot be created by an unprivileged process on Windows
    // (ERROR_PRIVILEGE_NOT_HELD / winerror 1314), so this test is Unix-only.
    #[test]
    #[cfg(unix)]
    fn test_long_symlink_target() {
        let temp = TempDir::new().unwrap();
        let target = temp.path().join("target.txt");
        fs::write(&target, b"Target content").unwrap();

        // Create a symlink with a very long target path
        let link = temp.path().join("link.txt");
        #[cfg(unix)]
        {
            // Create a very long relative target path
            let long_target = "very/long/relative/path/that/exceeds/the/traditional/tar/link/name/limit/of/100/characters/and/should/be/handled/by/gnu/longlink/extension/target.txt";
            std::os::unix::fs::symlink(long_target, &link).unwrap();
        }

        let mut tar_data = Vec::new();
        create_tar_stream(&[&link], &mut tar_data).unwrap();

        let dest = TempDir::new().unwrap();
        extract_tar_stream(Cursor::new(tar_data), dest.path()).unwrap();

        let extracted_link = dest.path().join("link.txt");
        let meta = extracted_link.symlink_metadata().unwrap();
        assert!(meta.file_type().is_symlink());
        #[cfg(unix)]
        {
            let meta = fs::read_link(&extracted_link).unwrap();
            // The link target should be preserved
            assert!(meta.to_string_lossy().contains("very/long/relative/path"));
        }
    }

    #[test]
    fn test_long_directory_path() {
        let temp = TempDir::new().unwrap();
        // Create a deeply nested directory with a very long path
        let mut long_dir = temp.path().to_path_buf();
        for i in 0..15 {
            long_dir = long_dir.join(format!("very_long_directory_name_{i}_that_exceeds_the_traditional_limit"));
            fs::create_dir_all(&long_dir).unwrap();
        }
        let file_in_long_dir = long_dir.join("file.txt");
        fs::write(&file_in_long_dir, b"Content in long dir").unwrap();

        // Verify path length exceeds 255 chars
        assert!(file_in_long_dir.to_string_lossy().len() > 255);

        // Create tar - pass the first directory to preserve full path
        let first_dir = temp.path().join("very_long_directory_name_0_that_exceeds_the_traditional_limit");
        let mut tar_data = Vec::new();
        create_tar_stream(&[&first_dir], &mut tar_data).unwrap();

        // Extract
        let dest = TempDir::new().unwrap();
        extract_tar_stream(Cursor::new(tar_data), dest.path()).unwrap();

        // Verify content
        let mut extracted = dest.path().join("very_long_directory_name_0_that_exceeds_the_traditional_limit");
        for i in 1..15 {
            extracted = extracted.join(format!("very_long_directory_name_{i}_that_exceeds_the_traditional_limit"));
        }
        extracted = extracted.join("file.txt");
        assert!(extracted.exists());
        assert_eq!(fs::read(extracted).unwrap(), b"Content in long dir");
    }
}