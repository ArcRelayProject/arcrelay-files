//! Shared-folder domain and filesystem service used by paired-device Remote Files
//! and the unauthenticated-browser Web Gateway.

mod directory_snapshots;
use directory_snapshots::{natural_folded_cmp, DirectorySnapshots};
mod directory_query;
use directory_query::DirectoryQueries;

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use image::ImageEncoder as _;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, FileError>;

#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("invalid file operation: {0}")]
    Invalid(String),
    #[error("file resource not found: {0}")]
    NotFound(String),
    #[error("directory snapshot expired: {0}")]
    DirectorySnapshotExpired(String),
    #[error("file resource conflict: {0}")]
    Conflict(String),
    #[error("file operation is not permitted: {0}")]
    PermissionDenied(String),
    #[error("directory query is too broad: {0}")]
    DirectoryQueryTooBroad(String),
    #[error("file size limit exceeded: {0}")]
    FileTooLarge(String),
    #[error("file storage is exhausted: {0}")]
    InsufficientStorage(String),
    #[error("file resource is unavailable: {0}")]
    Unavailable(String),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("file serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("password hashing failed: {0}")]
    PasswordHash(#[from] argon2::password_hash::Error),
    #[error("file task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
    #[error("image processing failed: {0}")]
    Image(#[from] image::ImageError),
}

impl FileError {
    fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Stable machine-readable category for transport and UI adapters.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "files.invalid_argument",
            Self::NotFound(_) => "files.not_found",
            Self::DirectorySnapshotExpired(_) => "files.directory_snapshot_expired",
            Self::Conflict(_) => "files.conflict",
            Self::PermissionDenied(_) => "files.permission_denied",
            Self::DirectoryQueryTooBroad(_)
            | Self::FileTooLarge(_)
            | Self::InsufficientStorage(_) => "files.resource_exhausted",
            Self::Unavailable(_) | Self::Io { .. } => "files.unavailable",
            Self::Serialization(_) | Self::PasswordHash(_) | Self::Task(_) | Self::Image(_) => {
                "files.internal"
            }
        }
    }
}

pub const STORED_SHARES_VERSION: u32 = 3;
pub const DEFAULT_DIRECTORY_PAGE_SIZE: usize = 100;
pub const MAX_DIRECTORY_PAGE_SIZE: usize = 500;
pub const MAX_TEXT_PREVIEW_BYTES: usize = 1024 * 1024;
const MAX_REMOTE_UPLOAD_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_THUMBNAIL_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_THUMBNAIL_DIMENSION: u32 = 4096;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
pub enum WebAccessMode {
    #[default]
    Disabled,
    Public,
    Password,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PasswordCredential {
    password_hash: String,
    pub changed_at_ms: i64,
}

impl PasswordCredential {
    pub fn new(password: &str) -> Result<Self> {
        validate_password(password)?;
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)?
            .to_string();
        Ok(Self {
            password_hash,
            changed_at_ms: now_ms(),
        })
    }

    pub fn verify(&self, password: &str) -> bool {
        PasswordHash::new(&self.password_hash)
            .ok()
            .is_some_and(|hash| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &hash)
                    .is_ok()
            })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
pub struct WebSharePolicy {
    pub mode: WebAccessMode,
    pub listed: bool,
    pub allow_preview: bool,
    pub allow_download: bool,
    pub slug: String,
    credential: Option<PasswordCredential>,
    pub credential_revision: u64,
}

impl Default for WebSharePolicy {
    fn default() -> Self {
        Self {
            mode: WebAccessMode::Disabled,
            listed: true,
            allow_preview: true,
            allow_download: true,
            slug: new_slug(),
            credential: None,
            credential_revision: 0,
        }
    }
}

impl WebSharePolicy {
    pub fn has_password(&self) -> bool {
        self.credential.is_some()
    }

    pub fn verify_password(&self, password: &str) -> bool {
        self.credential
            .as_ref()
            .is_some_and(|credential| credential.verify(password))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedDirectory {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub paired_device_writable: bool,
    pub web: WebSharePolicy,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
pub struct WebSharePolicyView {
    pub mode: WebAccessMode,
    pub listed: bool,
    pub allow_preview: bool,
    pub allow_download: bool,
    pub slug: String,
    pub has_password: bool,
    pub credential_revision: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
pub struct LocalSharedDirectory {
    pub id: String,
    pub name: String,
    pub path: String,
    pub writable: bool,
    pub web: WebSharePolicyView,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
pub struct WebSharePolicyUpdate {
    pub mode: WebAccessMode,
    pub listed: bool,
    pub allow_preview: bool,
    pub allow_download: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum FileKind {
    File,
    Folder,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PreviewKind {
    Text,
    Image,
    Audio,
    Video,
    None,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DirectorySortKey {
    #[default]
    Name,
    Modified,
    Type,
    Size,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub name: String,
    pub relative_path: String,
    pub kind: FileKind,
    pub size: u64,
    pub modified_at_ms: i64,
    pub media_type: String,
    pub preview_kind: PreviewKind,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryPage {
    pub path: String,
    pub entries: Vec<FileEntry>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TextPreview {
    pub text: String,
    pub truncated: bool,
    pub media_type: String,
}

#[derive(Debug, Clone)]
pub struct PreparedFile {
    pub path: PathBuf,
    pub entry: FileEntry,
}

#[derive(Debug, Clone)]
pub struct PreparedUpload {
    pub destination: PathBuf,
    pub overwrite: bool,
    pub expected_modified_at_ms: Option<i64>,
    pub entry: FileEntry,
}

#[derive(Debug, Clone)]
pub struct ImageThumbnail {
    pub bytes: Vec<u8>,
    pub media_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredSharesV3 {
    version: u32,
    shares: Vec<SharedDirectory>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredSharesV2 {
    version: u32,
    shares: Vec<SharedDirectoryV2>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SharedDirectoryV2 {
    id: String,
    name: String,
    path: PathBuf,
    writable: bool,
}

#[derive(Clone)]
pub struct FileShareService {
    config_path: PathBuf,
    config_directory: PathBuf,
    shares: Arc<RwLock<Vec<SharedDirectory>>>,
    directory_snapshots: Arc<std::sync::Mutex<DirectorySnapshots>>,
    directory_queries: Arc<DirectoryQueries>,
}

impl FileShareService {
    pub fn load(config_directory: &Path) -> std::io::Result<Arc<Self>> {
        std::fs::create_dir_all(config_directory)?;
        let config_directory = config_directory.canonicalize()?;
        let config_path = config_directory.join("remote-file-shares.json");
        let mut shares = if config_path.is_file() {
            load_stored_shares(&config_path)?
        } else {
            Vec::new()
        };
        shares = shares
            .into_iter()
            .filter_map(|mut share| {
                let path = share.path.canonicalize().ok()?;
                if !path.is_dir() || paths_overlap(&path, &config_directory) {
                    return None;
                }
                share.path = path;
                if !valid_slug(&share.web.slug) {
                    share.web.slug = new_slug();
                }
                Some(share)
            })
            .collect();
        ensure_unique_slugs(&mut shares);
        let service = Arc::new(Self {
            config_path,
            config_directory,
            shares: Arc::new(RwLock::new(shares)),
            directory_snapshots: Arc::new(std::sync::Mutex::new(DirectorySnapshots::default())),
            directory_queries: Arc::new(DirectoryQueries::default()),
        });
        service.persist()?;
        Ok(service)
    }

    pub fn local_shares(&self) -> Vec<LocalSharedDirectory> {
        self.read_shares().iter().map(local_share).collect()
    }

    pub fn shared_directory(&self, id: &str) -> Result<SharedDirectory> {
        self.read_shares()
            .iter()
            .find(|share| share.id == id)
            .cloned()
            .ok_or_else(|| FileError::NotFound("shared directory".into()))
    }

    pub fn web_share_by_slug(&self, slug: &str) -> Option<SharedDirectory> {
        self.read_shares()
            .iter()
            .find(|share| share.web.slug == slug && share.web.mode != WebAccessMode::Disabled)
            .cloned()
    }

    pub fn listed_web_shares(&self) -> Vec<SharedDirectory> {
        self.read_shares()
            .iter()
            .filter(|share| share.web.mode != WebAccessMode::Disabled && share.web.listed)
            .cloned()
            .collect()
    }

    pub fn has_web_shares(&self) -> bool {
        self.read_shares()
            .iter()
            .any(|share| share.web.mode != WebAccessMode::Disabled)
    }

    pub fn add_share(&self, path: &Path) -> Result<LocalSharedDirectory> {
        let path = path
            .canonicalize()
            .map_err(|error| FileError::io("failed to access the shared directory", error))?;
        if !path.is_dir() {
            return Err(FileError::Invalid("only directories can be shared".into()));
        }
        if paths_overlap(&path, &self.config_directory) {
            return Err(FileError::Invalid(
                "ArcRelay configuration, identity, and database directories cannot be shared"
                    .into(),
            ));
        }
        verify_directory_read_access(&path)?;
        let mut shares = self.write_shares();
        if let Some(existing) = shares.iter().find(|share| share.path == path) {
            return Ok(local_share(existing));
        }
        let share = SharedDirectory {
            id: uuid::Uuid::new_v4().to_string(),
            name: path
                .file_name()
                .and_then(OsStr::to_str)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("Shared directory")
                .to_string(),
            path,
            paired_device_writable: false,
            web: WebSharePolicy::default(),
        };
        let view = local_share(&share);
        shares.push(share);
        drop(shares);
        self.persist()
            .map_err(|error| FileError::io("failed to persist shared directories", error))?;
        Ok(view)
    }

    pub fn remove_share(&self, id: &str) -> Result<()> {
        let mut shares = self.write_shares();
        let before = shares.len();
        shares.retain(|share| share.id != id);
        if shares.len() == before {
            return Err(FileError::NotFound("shared directory".into()));
        }
        drop(shares);
        self.persist()
            .map_err(|error| FileError::io("failed to persist shared directories", error))
    }

    pub fn set_share_writable(&self, id: &str, writable: bool) -> Result<LocalSharedDirectory> {
        let mut shares = self.write_shares();
        let share = shares
            .iter_mut()
            .find(|share| share.id == id)
            .ok_or_else(|| FileError::NotFound("shared directory".into()))?;
        share.paired_device_writable = writable;
        let view = local_share(share);
        drop(shares);
        self.persist()
            .map_err(|error| FileError::io("failed to persist shared directories", error))?;
        Ok(view)
    }

    pub fn set_web_policy(
        &self,
        id: &str,
        update: WebSharePolicyUpdate,
        new_password: Option<&str>,
    ) -> Result<LocalSharedDirectory> {
        if update.mode == WebAccessMode::Password && new_password.is_none() {
            let share = self.shared_directory(id)?;
            if !share.web.has_password() {
                return Err(FileError::Invalid(
                    "password access mode requires a password".into(),
                ));
            }
        }
        let credential = new_password.map(PasswordCredential::new).transpose()?;
        let mut shares = self.write_shares();
        let share = shares
            .iter_mut()
            .find(|share| share.id == id)
            .ok_or_else(|| FileError::NotFound("shared directory".into()))?;
        let previous_mode = share.web.mode;
        share.web.mode = update.mode;
        share.web.listed = update.listed;
        share.web.allow_preview = update.allow_preview;
        share.web.allow_download = update.allow_download;
        if let Some(credential) = credential {
            share.web.credential = Some(credential);
            share.web.credential_revision = share.web.credential_revision.saturating_add(1);
        } else {
            let credential_removed =
                update.mode != WebAccessMode::Password && share.web.credential.take().is_some();
            if credential_removed || previous_mode != update.mode {
                share.web.credential_revision = share.web.credential_revision.saturating_add(1);
            }
        }
        let view = local_share(share);
        drop(shares);
        self.persist()
            .map_err(|error| FileError::io("failed to persist shared directories", error))?;
        Ok(view)
    }

    pub fn verify_web_password(&self, slug: &str, password: &str) -> Option<(String, u64)> {
        let share = self.web_share_by_slug(slug)?;
        if share.web.mode != WebAccessMode::Password || !share.web.verify_password(password) {
            return None;
        }
        Some((share.id, share.web.credential_revision))
    }

    pub async fn list_directory(
        &self,
        share_id: &str,
        relative_path: &str,
    ) -> Result<Vec<FileEntry>> {
        self.scan_directory(
            share_id,
            relative_path,
            false,
            None,
            DirectorySortKey::Name,
            false,
        )
        .await
    }

    pub async fn list_web_directory_page(
        &self,
        share_id: &str,
        relative_path: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<DirectoryPage> {
        self.list_directory_page_inner(
            share_id,
            relative_path,
            cursor,
            limit,
            None,
            DirectorySortKey::Name,
            false,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list_directory_page(
        &self,
        share_id: &str,
        relative_path: &str,
        cursor: Option<&str>,
        limit: usize,
        search: Option<&str>,
        sort_key: DirectorySortKey,
        descending: bool,
    ) -> Result<DirectoryPage> {
        self.list_directory_page_inner(
            share_id,
            relative_path,
            cursor,
            limit,
            search,
            sort_key,
            descending,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn list_directory_page_inner(
        &self,
        share_id: &str,
        relative_path: &str,
        cursor: Option<&str>,
        limit: usize,
        search: Option<&str>,
        sort_key: DirectorySortKey,
        descending: bool,
        reject_symlinks: bool,
    ) -> Result<DirectoryPage> {
        let requested = std::time::Instant::now();
        let limit = limit.clamp(1, MAX_DIRECTORY_PAGE_SIZE);
        let search = search.map(str::trim).filter(|query| !query.is_empty());
        if search
            .is_some_and(|query| query.chars().count() > 256 || query.chars().any(char::is_control))
        {
            return Err(FileError::Invalid("invalid directory search query".into()));
        }
        // Resolve and revalidate the share on every page, including cached pages.
        let share = self.shared_directory(share_id)?;
        let share_for_resolve = share.clone();
        let relative_for_resolve = relative_path.to_string();
        let permit = self
            .directory_queries
            .workers
            .clone()
            .acquire_owned()
            .await
            .map_err(|error| FileError::Unavailable(error.to_string()))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let directory = if reject_symlinks {
                resolve_web_existing(&share_for_resolve, &relative_for_resolve)?
            } else {
                resolve_existing(&share_for_resolve, &relative_for_resolve)?
            };
            if !directory.is_dir() {
                return Err(FileError::Invalid("target is not a directory".into()));
            }
            Ok(())
        })
        .await
        .map_err(|e| FileError::Unavailable(e.to_string()))??;
        let path = remote_path(&clean_relative_path(relative_path)?);
        let query = format!(
            "{}|{path:?}|{search:?}|{sort_key:?}|{descending}|{reject_symlinks}",
            serde_json::to_string(&share)?
        );
        if let Some(cursor) = cursor {
            return self
                .directory_snapshots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .page(&query, &path, cursor, limit);
        }
        let gate = self.directory_queries.gate(&query);
        let _flight = gate.lock().await;
        if let Some(page) = self
            .directory_snapshots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recent_page(&query, &path, requested, limit)?
        {
            return Ok(page);
        }
        let entries = self
            .scan_directory(
                share_id,
                relative_path,
                reject_symlinks,
                search,
                sort_key,
                descending,
            )
            .await?;
        self.directory_snapshots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(query, path, entries, limit)
    }

    pub async fn prepare_file(
        &self,
        share_id: &str,
        relative_path: &str,
        web: bool,
    ) -> Result<PreparedFile> {
        let share = self.shared_directory(share_id)?;
        let path = if web {
            resolve_web_existing(&share, relative_path)?
        } else {
            resolve_existing(&share, relative_path)?
        };
        let metadata = tokio::fs::metadata(&path)
            .await
            .map_err(|error| FileError::io("failed to read file metadata", error))?;
        if !metadata.is_file() {
            return Err(FileError::Invalid("target is not a file".into()));
        }
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| FileError::Invalid("file name is not valid text".into()))?
            .to_string();
        let mut entry = entry_from_metadata(
            name,
            remote_path(Path::new(relative_path)),
            &path,
            &metadata,
        );
        entry.media_type = detect_media_type(&path).await;
        entry.preview_kind = preview_kind_for_path_and_media(&path, &entry.media_type);
        Ok(PreparedFile { entry, path })
    }

    pub async fn text_preview(
        &self,
        share_id: &str,
        relative_path: &str,
        max_bytes: usize,
    ) -> Result<TextPreview> {
        let prepared = self.prepare_file(share_id, relative_path, true).await?;
        if prepared.entry.preview_kind != PreviewKind::Text {
            return Err(FileError::Invalid(
                "this file does not support safe text preview".into(),
            ));
        }
        let max_bytes = max_bytes.clamp(1, MAX_TEXT_PREVIEW_BYTES);
        let file = tokio::fs::File::open(&prepared.path)
            .await
            .map_err(|error| FileError::io("failed to open file for text preview", error))?;
        let mut bytes = Vec::with_capacity(max_bytes.saturating_add(1));
        use tokio::io::AsyncReadExt as _;
        file.take(max_bytes.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| FileError::io("failed to read text preview", error))?;
        let truncated = bytes.len() > max_bytes;
        bytes.truncate(max_bytes);
        let text = decode_text(&bytes)?;
        Ok(TextPreview {
            text,
            truncated,
            media_type: prepared.entry.media_type,
        })
    }

    pub async fn prepare_thumbnail(
        &self,
        share_id: &str,
        relative_path: &str,
        max_dimension: u32,
        web: bool,
    ) -> Result<Option<ImageThumbnail>> {
        let prepared = self.prepare_file(share_id, relative_path, web).await?;
        if prepared.entry.size > MAX_THUMBNAIL_SOURCE_BYTES
            || prepared.entry.preview_kind != PreviewKind::Image
        {
            return Ok(None);
        }
        let dimension = max_dimension.clamp(32, MAX_THUMBNAIL_DIMENSION);
        tokio::task::spawn_blocking(move || build_image_thumbnail(&prepared.path, dimension))
            .await?
    }

    pub async fn create_directory(
        &self,
        share_id: &str,
        relative_path: &str,
        name: &str,
    ) -> Result<FileEntry> {
        validate_name(name)?;
        let share = self.shared_directory(share_id)?;
        ensure_writable(&share)?;
        let parent = resolve_existing(&share, relative_path)?;
        if !parent.is_dir() {
            return Err(FileError::Invalid("target is not a directory".into()));
        }
        ensure_directory_accepts_writes(&parent)?;
        let path = parent.join(name);
        if !path.exists() {
            tokio::fs::create_dir(&path)
                .await
                .map_err(|error| describe_write_error("create directory", error))?;
        }
        let metadata = tokio::fs::metadata(&path)
            .await
            .map_err(|error| FileError::io("failed to read directory metadata", error))?;
        Ok(entry_from_metadata(
            name.to_string(),
            join_remote_path(relative_path, name),
            &path,
            &metadata,
        ))
    }

    pub async fn rename(
        &self,
        share_id: &str,
        relative_path: &str,
        new_name: &str,
    ) -> Result<FileEntry> {
        validate_name(new_name)?;
        let share = self.shared_directory(share_id)?;
        ensure_writable(&share)?;
        let source = resolve_existing(&share, relative_path)?;
        if source == share.path {
            return Err(FileError::Invalid(
                "the shared root directory cannot be renamed".into(),
            ));
        }
        let parent = source
            .parent()
            .ok_or_else(|| FileError::Invalid("invalid path".into()))?;
        let destination = parent.join(new_name);
        if destination.exists() {
            return Err(FileError::Conflict(
                "an item with the same name already exists".into(),
            ));
        }
        tokio::fs::rename(&source, &destination)
            .await
            .map_err(|error| FileError::io("failed to rename file item", error))?;
        let metadata = tokio::fs::metadata(&destination)
            .await
            .map_err(|error| FileError::io("failed to read renamed item metadata", error))?;
        let parent_relative = parent
            .strip_prefix(&share.path)
            .map_err(|_| FileError::Invalid("path escapes the shared directory".into()))?;
        Ok(entry_from_metadata(
            new_name.to_string(),
            join_remote_path(&remote_path(parent_relative), new_name),
            &destination,
            &metadata,
        ))
    }

    pub async fn delete(&self, share_id: &str, relative_path: &str) -> Result<()> {
        let share = self.shared_directory(share_id)?;
        ensure_writable(&share)?;
        let path = resolve_existing(&share, relative_path)?;
        if path == share.path {
            return Err(FileError::Invalid(
                "the shared root directory cannot be deleted".into(),
            ));
        }
        if path.is_dir() {
            tokio::fs::remove_dir_all(path)
                .await
                .map_err(|error| FileError::io("failed to delete directory", error))
        } else {
            tokio::fs::remove_file(path)
                .await
                .map_err(|error| FileError::io("failed to delete file", error))
        }
    }

    pub async fn prepare_upload(
        &self,
        share_id: &str,
        relative_path: &str,
        name: &str,
        size: u64,
        overwrite: bool,
        expected_modified_at_ms: Option<i64>,
    ) -> Result<PreparedUpload> {
        validate_name(name)?;
        let share = self.shared_directory(share_id)?;
        ensure_writable(&share)?;
        let parent = resolve_existing(&share, relative_path)?;
        if !parent.is_dir() {
            return Err(FileError::Invalid(
                "upload target is not a directory".into(),
            ));
        }
        ensure_directory_accepts_writes(&parent)?;
        if size > MAX_REMOTE_UPLOAD_BYTES {
            return Err(FileError::FileTooLarge(
                "a remote upload cannot exceed 4 GiB per file".into(),
            ));
        }
        if size
            > fs2::available_space(&parent)
                .map_err(|error| FileError::io("failed to query available disk space", error))?
        {
            return Err(FileError::InsufficientStorage(
                "insufficient disk space".into(),
            ));
        }
        let destination = parent.join(name);
        if destination.is_dir() {
            return Err(FileError::Conflict(
                "a directory with the same name already exists at the destination".into(),
            ));
        }
        if destination.exists() && !overwrite {
            return Err(FileError::Conflict(
                "the destination file already exists".into(),
            ));
        }
        if let Some(expected) = expected_modified_at_ms {
            let metadata =
                tokio::fs::metadata(&destination)
                    .await
                    .map_err(|error| FileError::Io {
                        context: "the remote file was deleted; the local edited copy was retained"
                            .into(),
                        source: error,
                    })?;
            if metadata_modified_at_ms(&metadata) != expected {
                return Err(FileError::Conflict(
                    "the remote file was modified elsewhere; the local edited copy was retained"
                        .into(),
                ));
            }
        }
        Ok(PreparedUpload {
            destination: destination.clone(),
            overwrite,
            expected_modified_at_ms,
            entry: FileEntry {
                name: name.to_string(),
                relative_path: join_remote_path(relative_path, name),
                kind: FileKind::File,
                size,
                modified_at_ms: now_ms(),
                media_type: media_type_for_path(&destination),
                preview_kind: preview_kind_for_path(&destination),
            },
        })
    }

    fn persist(&self) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(&StoredSharesV3 {
            version: STORED_SHARES_VERSION,
            shares: self.read_shares().clone(),
        })
        .map_err(std::io::Error::other)?;
        atomic_private_replace(&self.config_path, &bytes)
    }

    fn read_shares(&self) -> RwLockReadGuard<'_, Vec<SharedDirectory>> {
        self.shares
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_shares(&self) -> RwLockWriteGuard<'_, Vec<SharedDirectory>> {
        self.shares
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn sort_directory_entries(
    entries: &mut Vec<FileEntry>,
    sort_key: DirectorySortKey,
    descending: bool,
) {
    let mut keyed = std::mem::take(entries)
        .into_iter()
        .map(|entry| {
            let name = entry.name.to_lowercase();
            let extension = file_extension(&entry.name);
            (entry, name, extension)
        })
        .collect::<Vec<_>>();
    keyed.sort_by(
        |(left, left_name, left_ext), (right, right_name, right_ext)| {
            let kind = file_kind_order(left.kind).cmp(&file_kind_order(right.kind));
            if !kind.is_eq() {
                return kind;
            }
            let name = || {
                natural_folded_cmp(left_name, right_name).then_with(|| left.name.cmp(&right.name))
            };
            let order = match sort_key {
                DirectorySortKey::Name => name(),
                DirectorySortKey::Modified => left.modified_at_ms.cmp(&right.modified_at_ms),
                DirectorySortKey::Type => left_ext.cmp(right_ext),
                DirectorySortKey::Size => left.size.cmp(&right.size),
            };
            (if descending { order.reverse() } else { order })
                .then_with(name)
                .then_with(|| left.relative_path.cmp(&right.relative_path))
        },
    );
    entries.extend(keyed.into_iter().map(|(entry, _, _)| entry));
}

fn file_extension(name: &str) -> String {
    Path::new(name)
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_lowercase()
}

fn load_stored_shares(path: &Path) -> std::io::Result<Vec<SharedDirectory>> {
    let bytes = std::fs::read(path)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing store version")
        })?;
    match version {
        2 => {
            let stored: StoredSharesV2 =
                serde_json::from_value(value).map_err(std::io::Error::other)?;
            debug_assert_eq!(stored.version, 2);
            Ok(stored
                .shares
                .into_iter()
                .map(|share| SharedDirectory {
                    id: share.id,
                    name: share.name,
                    path: share.path,
                    paired_device_writable: share.writable,
                    web: WebSharePolicy::default(),
                })
                .collect())
        }
        3 => {
            let stored: StoredSharesV3 =
                serde_json::from_value(value).map_err(std::io::Error::other)?;
            Ok(stored.shares)
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported remote-file store version {other}"),
        )),
    }
}

fn atomic_private_replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("share store has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(OsStr::to_str).unwrap_or("shares"),
        uuid::Uuid::new_v4()
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    #[cfg(windows)]
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn verify_directory_read_access(path: &Path) -> Result<()> {
    let mut entries =
        std::fs::read_dir(path).map_err(|error| directory_read_access_error(path, error))?;
    if let Some(entry) = entries.next() {
        entry.map_err(|error| directory_read_access_error(path, error))?;
    }
    Ok(())
}

fn directory_read_access_error(path: &Path, error: std::io::Error) -> FileError {
    FileError::Io {
        context: format!(
            "failed to read shared directory \"{}\"; allow ArcRelay to access the directory or enable Full Disk Access in General settings",
            path.display()
        ),
        source: error,
    }
}

fn local_share(share: &SharedDirectory) -> LocalSharedDirectory {
    LocalSharedDirectory {
        id: share.id.clone(),
        name: share.name.clone(),
        path: share.path.to_string_lossy().into_owned(),
        writable: share.paired_device_writable,
        web: WebSharePolicyView {
            mode: share.web.mode,
            listed: share.web.listed,
            allow_preview: share.web.allow_preview,
            allow_download: share.web.allow_download,
            slug: share.web.slug.clone(),
            has_password: share.web.has_password(),
            credential_revision: share.web.credential_revision,
        },
    }
}

fn validate_password(password: &str) -> Result<()> {
    if password.len() < 8 {
        return Err(FileError::Invalid(
            "web access password must contain at least 8 characters".into(),
        ));
    }
    if password.len() > 256 {
        return Err(FileError::Invalid(
            "web access password cannot exceed 256 bytes".into(),
        ));
    }
    Ok(())
}

fn valid_slug(value: &str) -> bool {
    (8..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn new_slug() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..20].to_string()
}

fn ensure_unique_slugs(shares: &mut [SharedDirectory]) {
    let mut seen = std::collections::HashSet::new();
    for share in shares {
        while !seen.insert(share.web.slug.clone()) {
            share.web.slug = new_slug();
        }
    }
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

pub fn clean_relative_path(value: &str) -> Result<PathBuf> {
    if value.contains('\0') || value.contains('%') {
        return Err(FileError::Invalid(
            "path contains disallowed characters".into(),
        ));
    }
    let mut result = PathBuf::new();
    for component in Path::new(value).components() {
        match component {
            Component::Normal(value) => result.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(FileError::Invalid(
                    "path escapes the shared directory".into(),
                ))
            }
        }
    }
    Ok(result)
}

fn resolve_existing(share: &SharedDirectory, relative_path: &str) -> Result<PathBuf> {
    let relative = clean_relative_path(relative_path)?;
    let root = share
        .path
        .canonicalize()
        .map_err(|error| FileError::io("shared directory is unavailable", error))?;
    let path = root
        .join(relative)
        .canonicalize()
        .map_err(|error| FileError::io("remote path is unavailable", error))?;
    if !path.starts_with(&root) {
        return Err(FileError::Invalid(
            "path escapes the shared directory".into(),
        ));
    }
    Ok(path)
}

fn resolve_web_existing(share: &SharedDirectory, relative_path: &str) -> Result<PathBuf> {
    let relative = clean_relative_path(relative_path)?;
    let root = share
        .path
        .canonicalize()
        .map_err(|error| FileError::io("shared directory is unavailable", error))?;
    let mut candidate = root.clone();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(FileError::Invalid(
                "path escapes the shared directory".into(),
            ));
        };
        candidate.push(component);
        let metadata = std::fs::symlink_metadata(&candidate)
            .map_err(|error| FileError::io("web path is unavailable", error))?;
        if metadata.file_type().is_symlink() {
            return Err(FileError::PermissionDenied(
                "symbolic links are not allowed for web access".into(),
            ));
        }
    }
    let canonical = candidate
        .canonicalize()
        .map_err(|error| FileError::io("web path is unavailable", error))?;
    if !canonical.starts_with(&root) {
        return Err(FileError::Invalid(
            "path escapes the shared directory".into(),
        ));
    }
    Ok(canonical)
}

fn validate_name(name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed != name || matches!(name, "." | "..") {
        return Err(FileError::Invalid("invalid name".into()));
    }
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(FileError::Invalid(
            "name cannot contain path separators".into(),
        ));
    }
    Ok(())
}

fn ensure_writable(share: &SharedDirectory) -> Result<()> {
    if share.paired_device_writable {
        Ok(())
    } else {
        Err(FileError::PermissionDenied(
            "the shared directory is read-only".into(),
        ))
    }
}

fn ensure_directory_accepts_writes(directory: &Path) -> Result<()> {
    let metadata = std::fs::metadata(directory)
        .map_err(|error| FileError::io("failed to read target directory metadata", error))?;
    if metadata.permissions().readonly() {
        Err(FileError::PermissionDenied(
            "the target directory is read-only; change its permissions on the remote computer before writing"
                .into(),
        ))
    } else {
        Ok(())
    }
}

fn describe_write_error(action: &str, error: std::io::Error) -> FileError {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        FileError::PermissionDenied(format!(
            "failed to {action}: the target directory is read-only or the current user lacks write permission"
        ))
    } else {
        FileError::io(format!("failed to {action}"), error)
    }
}

fn entry_from_metadata(
    name: String,
    relative_path: String,
    path: &Path,
    metadata: &std::fs::Metadata,
) -> FileEntry {
    let kind = if metadata.is_dir() {
        FileKind::Folder
    } else {
        FileKind::File
    };
    FileEntry {
        name,
        relative_path,
        kind,
        size: if metadata.is_file() {
            metadata.len()
        } else {
            0
        },
        modified_at_ms: metadata_modified_at_ms(metadata),
        media_type: if metadata.is_file() {
            media_type_for_path(path)
        } else {
            "inode/directory".into()
        },
        preview_kind: if metadata.is_file() {
            preview_kind_for_path(path)
        } else {
            PreviewKind::None
        },
    }
}

fn media_type_for_path(path: &Path) -> String {
    mime_guess::from_path(path)
        .first_raw()
        .unwrap_or("application/octet-stream")
        .to_string()
}

async fn detect_media_type(path: &Path) -> String {
    let mut header = [0_u8; 8192];
    if let Ok(mut file) = tokio::fs::File::open(path).await {
        use tokio::io::AsyncReadExt as _;
        if let Ok(length) = file.read(&mut header).await {
            if let Some(kind) = infer::get(&header[..length]) {
                return kind.mime_type().to_string();
            }
        }
    }
    media_type_for_path(path)
}

fn preview_kind_for_path(path: &Path) -> PreviewKind {
    let media = media_type_for_path(path);
    preview_kind_for_path_and_media(path, &media)
}

fn preview_kind_for_path_and_media(path: &Path, media: &str) -> PreviewKind {
    if is_text_path(path, media) {
        PreviewKind::Text
    } else if matches!(
        media,
        "image/jpeg" | "image/png" | "image/gif" | "image/webp"
    ) {
        PreviewKind::Image
    } else if media.starts_with("audio/") {
        PreviewKind::Audio
    } else if media.starts_with("video/") {
        PreviewKind::Video
    } else {
        PreviewKind::None
    }
}

fn is_text_path(path: &Path, media: &str) -> bool {
    if media.starts_with("text/") {
        return true;
    }
    matches!(
        path.extension()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "txt"
            | "md"
            | "markdown"
            | "csv"
            | "json"
            | "xml"
            | "yaml"
            | "yml"
            | "toml"
            | "log"
            | "rs"
            | "swift"
            | "dart"
            | "kt"
            | "java"
            | "c"
            | "h"
            | "cpp"
            | "hpp"
            | "py"
            | "rb"
            | "go"
            | "sh"
            | "zsh"
            | "fish"
            | "ps1"
            | "ini"
            | "conf"
            | "cfg"
            | "css"
            | "scss"
            | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "html"
            | "htm"
            | "svg"
    )
}

fn decode_text(bytes: &[u8]) -> Result<String> {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        return String::from_utf16(&units)
            .map_err(|_| FileError::Invalid("invalid text encoding".into()));
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        return String::from_utf16(&units)
            .map_err(|_| FileError::Invalid("invalid text encoding".into()));
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    if bytes.contains(&0) {
        return Err(FileError::Invalid(
            "binary content detected; preview is unavailable".into(),
        ));
    }
    std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| {
        FileError::Invalid("text preview supports only UTF-8 or UTF-16 with a BOM".into())
    })
}

fn metadata_modified_at_ms(metadata: &std::fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

fn join_remote_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{}/{}", parent.trim_end_matches('/'), name)
    }
}

fn remote_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn file_kind_order(kind: FileKind) -> u8 {
    match kind {
        FileKind::Folder => 0,
        FileKind::File => 1,
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn build_image_thumbnail(path: &Path, max_dimension: u32) -> Result<Option<ImageThumbnail>> {
    let image = match image::open(path) {
        Ok(image) => image,
        Err(_) => return Ok(None),
    };
    let thumbnail = image.thumbnail(max_dimension, max_dimension).to_rgba8();
    let mut bytes = Vec::new();
    image::codecs::png::PngEncoder::new(&mut bytes).write_image(
        thumbnail.as_raw(),
        thumbnail.width(),
        thumbnail.height(),
        image::ExtendedColorType::Rgba8,
    )?;
    Ok(Some(ImageThumbnail {
        bytes,
        media_type: "image/png".into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_read_access_probe_opens_the_selected_path() {
        let shared = tempfile::tempdir().unwrap();
        std::fs::write(shared.path().join("visible.txt"), "visible").unwrap();
        assert!(verify_directory_read_access(shared.path()).is_ok());

        let error = verify_directory_read_access(&shared.path().join("visible.txt")).unwrap_err();
        assert!(error
            .to_string()
            .contains("failed to read shared directory"));
    }

    #[test]
    fn migrates_v2_without_enabling_web_access() {
        let directory = tempfile::tempdir().unwrap();
        let shared = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("remote-file-shares.json"),
            serde_json::json!({
                "version": 2,
                "shares": [{
                    "id": "kept-id",
                    "name": "资料",
                    "path": shared.path(),
                    "writable": true
                }]
            })
            .to_string(),
        )
        .unwrap();
        let service = FileShareService::load(directory.path()).unwrap();
        let shares = service.local_shares();
        assert_eq!(shares[0].id, "kept-id");
        assert!(shares[0].writable);
        assert_eq!(shares[0].web.mode, WebAccessMode::Disabled);
        let stored: serde_json::Value = serde_json::from_slice(
            &std::fs::read(directory.path().join("remote-file-shares.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(stored["version"], 3);
        assert!(stored.to_string().contains("pairedDeviceWritable"));
    }

    #[test]
    fn password_hash_never_appears_in_view() {
        let directory = tempfile::tempdir().unwrap();
        let shared = tempfile::tempdir().unwrap();
        let service = FileShareService::load(directory.path()).unwrap();
        let share = service.add_share(shared.path()).unwrap();
        let view = service
            .set_web_policy(
                &share.id,
                WebSharePolicyUpdate {
                    mode: WebAccessMode::Password,
                    listed: true,
                    allow_preview: true,
                    allow_download: true,
                },
                Some("correct horse battery staple"),
            )
            .unwrap();
        assert!(view.web.has_password);
        assert!(!serde_json::to_string(&view)
            .unwrap()
            .contains("passwordHash"));
        assert!(service
            .verify_web_password(&view.web.slug, "correct horse battery staple")
            .is_some());
    }

    #[test]
    fn rejects_encoded_and_parent_paths() {
        assert!(clean_relative_path("../secret").is_err());
        assert!(clean_relative_path("%252e%252e/secret").is_err());
        assert!(clean_relative_path("folder/file.txt").is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn web_access_rejects_symlinks() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let shared = tempfile::tempdir().unwrap();
        std::fs::write(shared.path().join("inside.txt"), "safe").unwrap();
        symlink(
            shared.path().join("inside.txt"),
            shared.path().join("alias.txt"),
        )
        .unwrap();
        let service = FileShareService::load(directory.path()).unwrap();
        let share = service.add_share(shared.path()).unwrap();
        assert!(service
            .prepare_file(&share.id, "alias.txt", true)
            .await
            .is_err());
        assert!(service
            .prepare_file(&share.id, "alias.txt", false)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn paginates_unicode_directories_and_decodes_utf16_preview() {
        let config = tempfile::tempdir().unwrap();
        let shared = tempfile::tempdir().unwrap();
        for name in ["中文.txt", "space name.txt", "emoji-📁.txt"] {
            std::fs::write(shared.path().join(name), "content").unwrap();
        }
        let utf16 = [0xff, 0xfe, b'h', 0, b'i', 0];
        std::fs::write(shared.path().join("utf16.txt"), utf16).unwrap();
        let service = FileShareService::load(config.path()).unwrap();
        let share = service.add_share(shared.path()).unwrap();
        let first = service
            .list_web_directory_page(&share.id, "", None, 2)
            .await
            .unwrap();
        assert_eq!(first.entries.len(), 2);
        assert!(first.next_cursor.is_some());
        let second = service
            .list_web_directory_page(&share.id, "", first.next_cursor.as_deref(), 2)
            .await
            .unwrap();
        assert_eq!(second.entries.len(), 2);
        assert!(second.next_cursor.is_none());
        assert_eq!(
            service
                .text_preview(&share.id, "utf16.txt", 512 * 1024)
                .await
                .unwrap()
                .text,
            "hi"
        );
    }

    #[tokio::test]
    async fn paired_directory_pages_search_and_sort_in_the_filesystem_service() {
        let config = tempfile::tempdir().unwrap();
        let shared = tempfile::tempdir().unwrap();
        for name in ["report-a.txt", "notes.txt", "REPORT-z.txt", "report-m.txt"] {
            std::fs::write(shared.path().join(name), "content").unwrap();
        }
        let service = FileShareService::load(config.path()).unwrap();
        let share = service.add_share(shared.path()).unwrap();

        let first = service
            .list_directory_page(
                &share.id,
                "",
                None,
                2,
                Some("report"),
                DirectorySortKey::Name,
                true,
            )
            .await
            .unwrap();
        assert_eq!(
            first
                .entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["REPORT-z.txt", "report-m.txt"]
        );
        assert!(first.next_cursor.is_some());

        let second = service
            .list_directory_page(
                &share.id,
                "",
                first.next_cursor.as_deref(),
                2,
                Some("report"),
                DirectorySortKey::Name,
                true,
            )
            .await
            .unwrap();
        assert_eq!(second.entries[0].name, "report-a.txt");
        assert!(second.next_cursor.is_none());
    }
}
