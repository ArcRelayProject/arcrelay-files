//! Online filesystem semantics shared by operating-system adapters.
use super::*;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

pub const MAX_FILE_RANGE_BYTES: u32 = 256 * 1024;

#[derive(Debug, Clone)]
pub struct FileStat {
    pub entry: FileEntry,
    pub revision: String,
}

fn revision(metadata: &std::fs::Metadata) -> String {
    let mut hash = Sha256::new();
    hash.update(metadata.len().to_le_bytes());
    for time in [metadata.modified(), metadata.created()] {
        hash.update(
            time.ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes(),
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        hash.update(metadata.dev().to_le_bytes());
        hash.update(metadata.ino().to_le_bytes());
        hash.update(metadata.ctime().to_le_bytes());
        hash.update(metadata.ctime_nsec().to_le_bytes());
    }
    format!("{:x}", hash.finalize())
}

fn existing(share: &SharedDirectory, relative: &str) -> Result<PathBuf> {
    if relative
        .split('/')
        .any(|part| part.starts_with(".arcrelay-upload-"))
    {
        return Err(FileError::Invalid(
            "upload staging files are not shared".into(),
        ));
    }
    // System folders deliberately do not expose symlinks or special files.
    // Resolving each component also rejects symlink escapes into another share.
    resolve_web_existing(share, relative).map_err(|error| match error {
        FileError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
            FileError::NotFound(relative.into())
        }
        error => error,
    })
}

fn split_path(path: &str) -> Result<(&str, &str)> {
    clean_relative_path(path)?;
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    validate_name(name)?;
    Ok((parent, name))
}

impl FileShareService {
    pub async fn stat(&self, share_id: &str, relative: &str) -> Result<FileStat> {
        let share = self.shared_directory(share_id)?;
        let path = existing(&share, relative)?;
        let metadata = tokio::fs::metadata(&path)
            .await
            .map_err(|error| FileError::io("failed to inspect file", error))?;
        if !metadata.is_file() && !metadata.is_dir() {
            return Err(FileError::Invalid("special files cannot be shared".into()));
        }
        let name = if relative.is_empty() {
            share.name.as_str()
        } else {
            split_path(relative)?.1
        };
        Ok(FileStat {
            entry: entry_from_metadata(name.into(), relative.into(), &path, &metadata),
            revision: revision(&metadata),
        })
    }

    pub async fn read_range(
        &self,
        share_id: &str,
        relative: &str,
        offset: u64,
        length: u32,
        expected: &str,
    ) -> Result<Vec<u8>> {
        if length == 0 || length > MAX_FILE_RANGE_BYTES || expected.is_empty() {
            return Err(FileError::Invalid("invalid file range or revision".into()));
        }
        let share = self.shared_directory(share_id)?;
        let path = existing(&share, relative)?;
        let mut file = tokio::fs::File::open(&path)
            .await
            .map_err(|error| FileError::io("failed to open file range", error))?;
        let metadata = file
            .metadata()
            .await
            .map_err(|error| FileError::io("failed to inspect file range", error))?;
        if !metadata.is_file() || revision(&metadata) != expected {
            return Err(FileError::Conflict(
                "file changed; reopen it to read the current version".into(),
            ));
        }
        let count = metadata.len().saturating_sub(offset).min(u64::from(length)) as usize;
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|error| FileError::io("failed to seek file", error))?;
        let mut bytes = vec![0; count];
        file.read_exact(&mut bytes)
            .await
            .map_err(|error| FileError::io("file changed while reading", error))?;
        let after = file
            .metadata()
            .await
            .map_err(|error| FileError::io("failed to verify file range", error))?;
        if revision(&after) != expected {
            return Err(FileError::Conflict("file changed while reading".into()));
        }
        Ok(bytes)
    }

    pub async fn move_entry(
        &self,
        share_id: &str,
        source: &str,
        destination: &str,
        overwrite: bool,
        expected: &str,
    ) -> Result<FileEntry> {
        let _guard = self.mutations.lock().await;
        let share = self.shared_directory(share_id)?;
        ensure_writable(&share)?;
        split_path(source)?; // Reject moving the shared root.
        if self.stat(share_id, source).await?.revision != expected {
            return Err(FileError::Conflict(
                "file changed before the move was applied".into(),
            ));
        }
        let source_path = existing(&share, source)?;
        let (parent, name) = split_path(destination)?;
        let destination_path = existing(&share, parent)?.join(name);
        if source_path == destination_path {
            return Ok(self.stat(share_id, source).await?.entry);
        }
        if destination_path.starts_with(&source_path) {
            return Err(FileError::Invalid(
                "cannot move a folder into itself".into(),
            ));
        }
        if let Ok(metadata) = tokio::fs::symlink_metadata(&destination_path).await {
            if !overwrite || !metadata.is_file() || metadata.is_symlink() || source_path.is_dir() {
                return Err(FileError::Conflict("destination already exists".into()));
            }
        }
        // Never delete a destination to implement overwrite: a failed rename
        // must leave both originals intact, including across mount boundaries.
        if overwrite {
            tokio::fs::rename(&source_path, &destination_path)
                .await
                .map_err(|error| describe_write_error("move file", error))?;
        } else {
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                &source_path,
                rustix::fs::CWD,
                &destination_path,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|error| {
                if error == rustix::io::Errno::EXIST {
                    FileError::Conflict("destination already exists".into())
                } else {
                    describe_write_error("move file", error.into())
                }
            })?;
            #[cfg(windows)]
            {
                use std::os::windows::ffi::OsStrExt;
                let source: Vec<u16> = source_path
                    .as_os_str()
                    .encode_wide()
                    .chain(Some(0))
                    .collect();
                let destination: Vec<u16> = destination_path
                    .as_os_str()
                    .encode_wide()
                    .chain(Some(0))
                    .collect();
                // No MOVEFILE_REPLACE_EXISTING: reject an external concurrent create.
                if unsafe {
                    windows_sys::Win32::Storage::FileSystem::MoveFileExW(
                        source.as_ptr(),
                        destination.as_ptr(),
                        0,
                    )
                } == 0
                {
                    let error = std::io::Error::last_os_error();
                    return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
                        FileError::Conflict("destination already exists".into())
                    } else {
                        describe_write_error("move file", error)
                    });
                }
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
            return Err(FileError::Invalid(
                "safe no-replace moves are not supported by this host yet".into(),
            ));
        }
        Ok(self.stat(share_id, destination).await?.entry)
    }

    pub async fn conditional_delete(
        &self,
        share_id: &str,
        relative: &str,
        expected: &str,
        recursive: bool,
    ) -> Result<()> {
        let _guard = self.mutations.lock().await;
        split_path(relative)?;
        let share = self.shared_directory(share_id)?;
        ensure_writable(&share)?;
        let path = existing(&share, relative)?;
        let current = self.stat(share_id, relative).await?;
        if current.revision != expected {
            return Err(FileError::Conflict(
                "file changed before deletion was applied".into(),
            ));
        }
        if current.entry.kind == FileKind::Folder {
            if recursive {
                tokio::fs::remove_dir_all(path).await
            } else {
                tokio::fs::remove_dir(path).await
            }
        } else {
            tokio::fs::remove_file(path).await
        }
        .map_err(|e| describe_write_error("delete file", e))
    }

    /// Validate and publish a staged upload while serializing ArcRelay writes.
    /// A missing expected revision means create-only, never unconditional overwrite.
    pub async fn commit_system_upload(
        &self,
        share_id: &str,
        relative: &str,
        name: &str,
        temporary: &Path,
        expected: &str,
    ) -> Result<FileStat> {
        let _guard = self.mutations.lock().await;
        validate_name(name)?;
        let share = self.shared_directory(share_id)?;
        ensure_writable(&share)?;
        let parent = existing(&share, relative)?;
        if temporary.parent() != Some(parent.as_path()) {
            return Err(FileError::Conflict(
                "upload destination moved while saving".into(),
            ));
        }
        let target = parent.join(name);
        let relative_target = join_remote_path(relative, name);
        if expected.is_empty() {
            tokio::fs::hard_link(temporary, &target)
                .await
                .map_err(|error| {
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        FileError::Conflict("destination already exists".into())
                    } else {
                        describe_write_error("publish new file", error)
                    }
                })?;
            let _ = tokio::fs::remove_file(temporary).await;
        } else {
            let current = self.stat(share_id, &relative_target).await?;
            if current.entry.kind != FileKind::File || current.revision != expected {
                return Err(FileError::Conflict(
                    "file changed elsewhere; the local save was retained".into(),
                ));
            }
            tokio::fs::rename(temporary, &target)
                .await
                .map_err(|error| describe_write_error("publish saved file", error))?;
        }
        self.stat(share_id, &relative_target).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Arc<FileShareService>, String, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("shared");
        std::fs::create_dir(&root).unwrap();
        let service = FileShareService::load(&temp.path().join("config")).unwrap();
        let share = service.add_share(&root).unwrap();
        service.set_share_writable(&share.id, true).unwrap();
        (temp, service, share.id, root.canonicalize().unwrap())
    }

    #[test]
    fn system_folder_service_constructs_without_runtime() {
        let _ = setup();
    }

    #[tokio::test]
    async fn system_folder_ranges_reject_changed_versions_and_handle_eof() {
        let (_temp, service, id, root) = setup();
        std::fs::write(root.join("hello.txt"), b"0123456789").unwrap();
        let before = service.stat(&id, "hello.txt").await.unwrap();
        assert_eq!(
            service
                .read_range(&id, "hello.txt", 3, 4, &before.revision)
                .await
                .unwrap(),
            b"3456"
        );
        assert!(service
            .read_range(&id, "hello.txt", 20, 4, &before.revision)
            .await
            .unwrap()
            .is_empty());
        std::fs::write(root.join("hello.txt"), b"changed").unwrap();
        assert!(matches!(
            service
                .read_range(&id, "hello.txt", 0, 4, &before.revision)
                .await,
            Err(FileError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn system_folder_moves_folders_and_rejects_invalid_destinations() {
        let (_temp, service, id, root) = setup();
        std::fs::create_dir(root.join("one")).unwrap();
        std::fs::create_dir(root.join("two")).unwrap();
        std::fs::write(root.join("one/a"), b"a").unwrap();
        let revision = service.stat(&id, "one").await.unwrap().revision;
        assert!(service
            .move_entry(&id, "one", "one/child", false, &revision)
            .await
            .is_err());
        assert!(service
            .move_entry(&id, "", "renamed", false, &revision)
            .await
            .is_err());
        assert!(service
            .move_entry(&id, "one", "../escape", false, &revision)
            .await
            .is_err());
        service
            .move_entry(&id, "one", "two/moved", false, &revision)
            .await
            .unwrap();
        assert_eq!(std::fs::read(root.join("two/moved/a")).unwrap(), b"a");
        service.set_share_writable(&id, false).unwrap();
        assert!(matches!(
            service
                .move_entry(&id, "two", "three", false, &revision)
                .await,
            Err(FileError::PermissionDenied(_))
        ));
    }

    #[tokio::test]
    async fn system_folder_delete_checks_revision_and_recursive_intent() {
        let (_temp, service, id, root) = setup();
        std::fs::create_dir(root.join("dir")).unwrap();
        std::fs::write(root.join("dir/a"), b"original").unwrap();
        let old = service.stat(&id, "dir/a").await.unwrap();
        std::fs::write(root.join("dir/a"), b"modified").unwrap();
        assert!(matches!(
            service
                .conditional_delete(&id, "dir/a", &old.revision, false)
                .await,
            Err(FileError::Conflict(_))
        ));
        assert!(matches!(
            service
                .move_entry(&id, "dir/a", "b", false, &old.revision)
                .await,
            Err(FileError::Conflict(_))
        ));
        let dir = service.stat(&id, "dir").await.unwrap();
        assert!(service
            .conditional_delete(&id, "dir", &dir.revision, false)
            .await
            .is_err());
        assert!(root.join("dir/a").exists());
        service
            .conditional_delete(&id, "dir", &dir.revision, true)
            .await
            .unwrap();
        assert!(!root.join("dir").exists());
        assert!(service
            .conditional_delete(&id, "", "anything", true)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn system_folder_save_rejects_stale_revisions_and_preserves_both_files() {
        let (_temp, service, id, root) = setup();
        std::fs::write(root.join("a"), b"original").unwrap();
        let before = service.stat(&id, "a").await.unwrap();
        std::fs::write(root.join("a"), b"another edit").unwrap();
        let staged = root.join(".arcrelay-upload-test");
        std::fs::write(&staged, b"local edit").unwrap();
        assert!(matches!(
            service
                .commit_system_upload(&id, "", "a", &staged, &before.revision)
                .await,
            Err(FileError::Conflict(_))
        ));
        assert_eq!(std::fs::read(root.join("a")).unwrap(), b"another edit");
        assert_eq!(std::fs::read(&staged).unwrap(), b"local edit");
        let current = service.stat(&id, "a").await.unwrap();
        service
            .commit_system_upload(&id, "", "a", &staged, &current.revision)
            .await
            .unwrap();
        assert_eq!(std::fs::read(root.join("a")).unwrap(), b"local edit");
    }
}
