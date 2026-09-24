//! Filesystem notifications invalidate only directories a receiver has viewed.
//! Epoch changes explicitly request reconciliation when an event cannot be replayed.
use crate::{FileError, FileShareService, Result};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    collections::{BTreeSet, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Notify;

const MAX_EVENTS: usize = 10_000;
const PAGE_SIZE: usize = 200;
const WAIT: Duration = Duration::from_secs(25);

struct State {
    epoch: String,
    sequence: u64,
    events: VecDeque<(u64, String)>,
}

impl State {
    fn new() -> Self {
        Self {
            epoch: uuid::Uuid::new_v4().to_string(),
            sequence: 0,
            events: VecDeque::new(),
        }
    }

    fn record(&mut self, directory: String) {
        self.sequence += 1;
        self.events.push_back((self.sequence, directory));
        if self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

pub(crate) struct ChangeFeed {
    state: Arc<Mutex<State>>,
    wake: Arc<Notify>,
    _watcher: Mutex<RecommendedWatcher>,
}

impl ChangeFeed {
    pub(crate) fn invalidate(&self) {
        self.state.lock().unwrap().reset();
        self.wake.notify_waiters();
    }

    fn start(root: PathBuf) -> Result<Arc<Self>> {
        let state = Arc::new(Mutex::new(State::new()));
        let wake = Arc::new(Notify::new());
        let callback_state = state.clone();
        let callback_wake = wake.clone();
        let callback_root = root.clone();
        let mut watcher = notify::recommended_watcher(move |event: notify::Result<Event>| {
            let mut state = callback_state.lock().unwrap();
            match event {
                Ok(event) => {
                    let mut directories = BTreeSet::new();
                    for path in event.paths {
                        if let Ok(relative) = path.strip_prefix(&callback_root) {
                            if relative.components().any(|part| {
                                part.as_os_str()
                                    .to_string_lossy()
                                    .starts_with(".arcrelay-upload-")
                            }) {
                                continue;
                            }
                            let parent = relative.parent().unwrap_or(Path::new(""));
                            directories.insert(remote_path(parent));
                            if path.is_dir() {
                                directories.insert(remote_path(relative));
                            }
                        }
                    }
                    for directory in directories {
                        state.record(directory);
                    }
                }
                Err(_) => state.reset(),
            }
            callback_wake.notify_waiters();
        })
        .map_err(|error| FileError::Unavailable(error.to_string()))?;
        watcher
            .watch(&root, RecursiveMode::Recursive)
            .map_err(|error| FileError::Unavailable(error.to_string()))?;
        Ok(Arc::new(Self {
            state,
            wake,
            _watcher: Mutex::new(watcher),
        }))
    }

    async fn wait(&self, epoch: &str, after: u64) -> (String, u64, Vec<String>, bool) {
        loop {
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let (result, idle_cursor) = {
                let state = self.state.lock().unwrap();
                let reset = epoch != state.epoch
                    || after > state.sequence
                    || state
                        .events
                        .front()
                        .is_some_and(|(first, _)| after.saturating_add(1) < *first);
                let result = if reset {
                    Some((state.epoch.clone(), state.sequence, Vec::new(), true))
                } else {
                    let mut directories = BTreeSet::new();
                    let mut next = None;
                    for (sequence, path) in state
                        .events
                        .iter()
                        .filter(|(sequence, _)| *sequence > after)
                    {
                        if directories.len() >= PAGE_SIZE && !directories.contains(path) {
                            break;
                        }
                        directories.insert(path.clone());
                        next = Some(*sequence);
                    }
                    next.map(|sequence| {
                        (
                            state.epoch.clone(),
                            sequence,
                            directories.into_iter().collect(),
                            false,
                        )
                    })
                };
                (result, (state.epoch.clone(), state.sequence))
            };
            if let Some(result) = result {
                return result;
            }
            if tokio::time::timeout(WAIT, notified).await.is_err() {
                return (idle_cursor.0, idle_cursor.1, Vec::new(), false);
            }
        }
    }
}

fn remote_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

impl FileShareService {
    pub async fn watch_changes(
        &self,
        share_id: &str,
        epoch: &str,
        after: u64,
    ) -> Result<(String, u64, Vec<String>, bool)> {
        let share = self.shared_directory(share_id)?;
        let feed = {
            let mut feeds = self.change_feeds.lock().unwrap();
            match feeds.get(share_id) {
                Some(feed) => feed.clone(),
                None => {
                    let feed = ChangeFeed::start(share.path)?;
                    feeds.insert(share_id.to_owned(), feed.clone());
                    feed
                }
            }
        };
        Ok(feed.wait(epoch, after).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cursor_replays_changes_and_resets_expired_history() {
        let temporary = tempfile::tempdir().unwrap();
        let feed = ChangeFeed::start(temporary.path().to_path_buf()).unwrap();
        let (epoch, _, _, reset) = feed.wait("", 0).await;
        assert!(reset);
        {
            let mut state = feed.state.lock().unwrap();
            state.record("one".into());
            state.record("two".into());
        }
        let (_, sequence, directories, reset) = feed.wait(&epoch, 0).await;
        assert_eq!(directories, ["one", "two"]);
        assert_eq!(sequence, 2);
        assert!(!reset);
        {
            let mut state = feed.state.lock().unwrap();
            for _ in 0..1_000 {
                state.record("one".into());
            }
        }
        let (_, latest, directories, reset) = feed.wait(&epoch, sequence).await;
        assert_eq!(directories, ["one"]);
        assert_eq!(latest, 1_002);
        assert!(!reset);
        feed.state.lock().unwrap().reset();
        assert!(feed.wait(&epoch, sequence).await.3);
    }
}
