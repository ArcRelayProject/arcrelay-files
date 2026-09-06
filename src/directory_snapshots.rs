//! Bounded immutable directory snapshots: later pages never rescan or reorder a listing.
use super::{DirectoryPage, FileEntry, FileError, Result};
use std::{
    cmp::Ordering,
    collections::VecDeque,
    time::{Duration, Instant},
};

const TTL: Duration = Duration::from_secs(300);
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_SNAPSHOTS: usize = 16;

struct Snapshot {
    id: String,
    query: String,
    created: Instant,
    entries: Vec<FileEntry>,
    bytes: usize,
}
#[derive(Default)]
pub(super) struct DirectorySnapshots {
    snapshots: VecDeque<Snapshot>,
}
impl DirectorySnapshots {
    pub fn insert(
        &mut self,
        query: String,
        path: String,
        entries: Vec<FileEntry>,
        limit: usize,
    ) -> Result<DirectoryPage> {
        let bytes = entries
            .iter()
            .map(|e| {
                std::mem::size_of::<FileEntry>()
                    + e.name.len()
                    + e.relative_path.len()
                    + e.media_type.len()
            })
            .sum::<usize>();
        if bytes > MAX_BYTES {
            return Err(FileError::DirectoryQueryTooBroad(
                "the directory is too large; use search to narrow the results".into(),
            ));
        }
        self.snapshots.retain(|s| s.created.elapsed() < TTL);
        while self.snapshots.len() >= MAX_SNAPSHOTS
            || self.snapshots.iter().map(|s| s.bytes).sum::<usize>() + bytes > MAX_BYTES
        {
            self.snapshots.pop_front();
        }
        let id = uuid::Uuid::new_v4().to_string();
        self.snapshots.push_back(Snapshot {
            id: id.clone(),
            query: query.clone(),
            created: Instant::now(),
            entries,
            bytes,
        });
        self.page(&query, &path, &format!("{id}:0"), limit)
    }
    pub fn recent_page(
        &mut self,
        query: &str,
        path: &str,
        requested: Instant,
        limit: usize,
    ) -> Result<Option<DirectoryPage>> {
        let cursor = self
            .snapshots
            .iter()
            .rev()
            .find(|s| s.query == query && s.created >= requested)
            .map(|s| format!("{}:0", s.id));
        cursor
            .map(|cursor| self.page(query, path, &cursor, limit))
            .transpose()
    }
    pub fn page(
        &mut self,
        query: &str,
        path: &str,
        cursor: &str,
        limit: usize,
    ) -> Result<DirectoryPage> {
        self.snapshots.retain(|s| s.created.elapsed() < TTL);
        let (id, offset) = cursor
            .split_once(':')
            .ok_or_else(|| FileError::Invalid("invalid directory pagination cursor".into()))?;
        let offset = offset
            .parse::<usize>()
            .map_err(|_| FileError::Invalid("invalid directory pagination cursor".into()))?;
        let snapshot = self
            .snapshots
            .iter()
            .find(|s| s.id == id && s.query == query)
            .ok_or_else(|| {
                FileError::DirectorySnapshotExpired(
                    "the directory snapshot expired; refresh it".into(),
                )
            })?;
        if offset > snapshot.entries.len() {
            return Err(FileError::Invalid(
                "invalid directory pagination cursor".into(),
            ));
        }
        let end = offset.saturating_add(limit).min(snapshot.entries.len());
        Ok(DirectoryPage {
            path: path.to_owned(),
            entries: snapshot.entries[offset..end].to_vec(),
            next_cursor: (end < snapshot.entries.len()).then(|| format!("{id}:{end}")),
        })
    }
}

/// Compare digit runs by magnitude without integer parsing/overflow; original spelling
/// breaks equal numeric values deterministically across platforms and pages.
pub(super) fn natural_folded_cmp(left: &str, right: &str) -> Ordering {
    let (mut a, mut b) = (left, right);
    while !a.is_empty() && !b.is_empty() {
        let ac = a.chars().next().unwrap();
        let bc = b.chars().next().unwrap();
        if ac.is_ascii_digit() && bc.is_ascii_digit() {
            let an = a.bytes().take_while(u8::is_ascii_digit).count();
            let bn = b.bytes().take_while(u8::is_ascii_digit).count();
            let av = a[..an].trim_start_matches('0');
            let bv = b[..bn].trim_start_matches('0');
            let order = av.len().cmp(&bv.len()).then_with(|| av.cmp(bv));
            if !order.is_eq() {
                return order;
            }
            a = &a[an..];
            b = &b[bn..];
        } else {
            let order = ac.cmp(&bc);
            if !order.is_eq() {
                return order;
            }
            a = &a[ac.len_utf8()..];
            b = &b[bc.len_utf8()..];
        }
    }
    a.len().cmp(&b.len()).then_with(|| left.cmp(right))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileKind, PreviewKind};
    fn entry(name: &str) -> FileEntry {
        FileEntry {
            name: name.into(),
            relative_path: name.into(),
            kind: FileKind::File,
            size: 0,
            modified_at_ms: 0,
            media_type: String::new(),
            preview_kind: PreviewKind::None,
        }
    }
    #[test]
    fn stable_pages_are_bound_to_query_and_expire() {
        let mut cache = DirectorySnapshots::default();
        let first = cache
            .insert(
                "policy-a".into(),
                "".into(),
                vec![entry("a"), entry("b"), entry("c")],
                1,
            )
            .unwrap();
        let cursor = first.next_cursor.unwrap();
        assert!(cache.page("policy-b", "", &cursor, 1).is_err());
        assert_eq!(
            cache.page("policy-a", "", &cursor, 1).unwrap().entries[0].name,
            "b"
        );
        cache.snapshots[0].created = Instant::now() - TTL;
        assert!(cache.page("policy-a", "", &cursor, 1).is_err());
    }
    #[test]
    fn natural_numbers_are_stable_without_overflow() {
        let mut names = vec![
            "file10",
            "file2",
            "file01",
            "file1",
            "file99999999999999999999",
            "FILE2",
        ];
        names.sort_by(|a, b| {
            natural_folded_cmp(&a.to_lowercase(), &b.to_lowercase()).then_with(|| a.cmp(b))
        });
        assert_eq!(
            names,
            [
                "file01",
                "file1",
                "FILE2",
                "file2",
                "file10",
                "file99999999999999999999"
            ]
        );
    }
}
