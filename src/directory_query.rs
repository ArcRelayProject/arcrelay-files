use super::*;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex, Weak,
};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

const SCAN_BYTES: usize = 24 * 1024 * 1024;
const SCAN_ENTRIES: usize = 100_000;
const SCAN_DURATION: Duration = Duration::from_secs(5);

pub(super) struct DirectoryQueries {
    gates: Mutex<HashMap<String, Weak<AsyncMutex<()>>>>,
    pub(super) workers: Arc<Semaphore>,
}
impl Default for DirectoryQueries {
    fn default() -> Self {
        Self {
            gates: Mutex::new(HashMap::new()),
            workers: Arc::new(Semaphore::new(2)),
        }
    }
}
impl DirectoryQueries {
    pub fn gate(&self, query: &str) -> Arc<AsyncMutex<()>> {
        let mut gates = self
            .gates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(gate) = gates.get(query).and_then(Weak::upgrade) {
            return gate;
        }
        gates.retain(|_, gate| gate.strong_count() > 0);
        let gate = Arc::new(AsyncMutex::new(()));
        gates.insert(query.into(), Arc::downgrade(&gate));
        gate
    }
}

struct CancelScan(Arc<AtomicBool>);
impl Drop for CancelScan {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl FileShareService {
    pub(super) async fn scan_directory(
        &self,
        share_id: &str,
        relative: &str,
        reject_symlinks: bool,
        search: Option<&str>,
        sort: DirectorySortKey,
        descending: bool,
    ) -> Result<Vec<FileEntry>> {
        let share = self.shared_directory(share_id)?;
        let relative = relative.to_string();
        let search = search.map(str::to_lowercase);
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel = CancelScan(cancelled.clone());
        let queries = self.directory_queries.clone();
        // The permit stays with the blocking worker even if its caller is cancelled.
        let permit = queries
            .workers
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| FileError::Unavailable(e.to_string()))?;
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let directory = if reject_symlinks {
                resolve_web_existing(&share, &relative)?
            } else {
                resolve_existing(&share, &relative)?
            };
            let reader = std::fs::read_dir(&directory)
                .map_err(|e| FileError::io("failed to read directory", e))?;
            let started = Instant::now();
            let mut bytes = 0usize;
            let mut entries = Vec::new();
            for (scanned, item) in reader.enumerate() {
                if cancelled.load(Ordering::Acquire) {
                    return Err(FileError::Unavailable("directory query cancelled".into()));
                }
                if scanned >= SCAN_ENTRIES || started.elapsed() > SCAN_DURATION {
                    return Err(FileError::DirectoryQueryTooBroad(
                        "directory scan budget exceeded".into(),
                    ));
                }
                let item = item.map_err(|e| FileError::io("failed to read directory entry", e))?;
                let name = item.file_name().to_string_lossy().into_owned();
                if search
                    .as_ref()
                    .is_some_and(|query| !name.to_lowercase().contains(query))
                {
                    continue;
                }
                let Ok(file_type) = item.file_type() else {
                    continue;
                };
                if reject_symlinks && file_type.is_symlink() {
                    continue;
                }
                let path = item.path();
                let Ok(canonical) = path.canonicalize() else {
                    continue;
                };
                if !canonical.starts_with(&share.path) {
                    continue;
                }
                let Ok(metadata) = std::fs::metadata(&canonical) else {
                    continue;
                };
                let child = join_remote_path(&relative, &name);
                let entry = entry_from_metadata(name, child, &path, &metadata);
                // Include cached lowercase/extension keys and vector allocation slack.
                bytes = bytes.saturating_add(
                    std::mem::size_of::<FileEntry>() * 2
                        + entry.name.len() * 3
                        + entry.relative_path.len()
                        + entry.media_type.len(),
                );
                if bytes > SCAN_BYTES {
                    return Err(FileError::DirectoryQueryTooBroad(
                        "directory memory budget exceeded; narrow the search".into(),
                    ));
                }
                entries.push(entry);
            }
            sort_directory_entries(&mut entries, sort, descending);
            if cancelled.load(Ordering::Acquire) {
                return Err(FileError::Unavailable("directory query cancelled".into()));
            }
            Ok(entries)
        });
        let result = worker
            .await
            .map_err(|e| FileError::Unavailable(e.to_string()))?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn construction_and_single_flight_need_no_runtime() {
        let queries = DirectoryQueries::default();
        let first = queries.gate("query");
        assert!(Arc::ptr_eq(&first, &queries.gate("query")));
        assert!(!Arc::ptr_eq(&first, &queries.gate("other")));
    }
}
