use super::*;
use image::{ImageEncoder as _, ImageReader};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const MAX_PIXELS: u64 = 8 * 1024 * 1024;
const WORK_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ENCODED_BYTES: usize = 4 * 1024 * 1024;
const CACHE_BYTES: usize = 32 * 1024 * 1024;
const CACHE_ENTRIES: usize = 64;
const CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Default)]
pub(super) struct ThumbnailCache {
    entries: HashMap<String, (Instant, ImageThumbnail)>,
    bytes: usize,
}

impl ThumbnailCache {
    fn get(&self, key: &str) -> Option<ImageThumbnail> {
        self.entries
            .get(key)
            .filter(|(at, _)| at.elapsed() < CACHE_TTL)
            .map(|(_, value)| value.clone())
    }

    fn insert(&mut self, key: String, thumbnail: ImageThumbnail) {
        self.entries.retain(|_, (at, _)| at.elapsed() < CACHE_TTL);
        self.bytes = self
            .entries
            .values()
            .map(|(_, value)| value.bytes.len())
            .sum();
        if let Some((_, old)) = self.entries.remove(&key) {
            self.bytes -= old.bytes.len();
        }
        while self.entries.len() >= CACHE_ENTRIES
            || self.bytes + thumbnail.bytes.len() > CACHE_BYTES
        {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some((_, value)) = self.entries.remove(&oldest) {
                self.bytes -= value.bytes.len();
            }
        }
        self.bytes += thumbnail.bytes.len();
        self.entries.insert(key, (Instant::now(), thumbnail));
    }
}

impl FileShareService {
    pub async fn prepare_thumbnail(
        &self,
        share_id: &str,
        relative_path: &str,
        max_dimension: u32,
        web: bool,
    ) -> Result<Option<ImageThumbnail>> {
        // Revalidate access even for cached thumbnails.
        let prepared = self.prepare_file(share_id, relative_path, web).await?;
        if prepared.entry.size > MAX_THUMBNAIL_SOURCE_BYTES
            || prepared.entry.preview_kind != PreviewKind::Image
        {
            return Ok(None);
        }
        let dimension = max_dimension.clamp(32, MAX_THUMBNAIL_DIMENSION);
        let metadata = tokio::fs::metadata(&prepared.path)
            .await
            .map_err(|error| FileError::io("failed to inspect thumbnail source", error))?;
        let key = format!(
            "thumbnail:{:?}:{:?}:{}:{dimension}",
            prepared.path,
            metadata.modified().ok(),
            metadata.len()
        );
        let cached = || {
            self.thumbnails
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&key)
        };
        if let Some(value) = cached() {
            return Ok(Some(value));
        }
        let gate = self.directory_queries.gate(&key);
        let flight = gate.lock_owned().await;
        if let Some(value) = cached() {
            return Ok(Some(value));
        }
        let permit = self
            .resources
            .work(WORK_BYTES)
            .await
            .map_err(|error| FileError::Unavailable(error.to_string()))?;
        let result = tokio::task::spawn_blocking(move || {
            let _flight = flight;
            let _permit = permit;
            build_image_thumbnail(&prepared.path, dimension)
        })
        .await??;
        if let Some(thumbnail) = &result {
            self.thumbnails
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(key, thumbnail.clone());
        }
        Ok(result)
    }
}

fn valid_dimensions(width: u32, height: u32) -> bool {
    width > 0
        && height > 0
        && width <= 16_384
        && height <= 16_384
        && u64::from(width) * u64::from(height) <= MAX_PIXELS
}

fn build_image_thumbnail(path: &Path, dimension: u32) -> Result<Option<ImageThumbnail>> {
    let (width, height) = match ImageReader::open(path)
        .map_err(|error| FileError::io("failed to open thumbnail source", error))?
        .with_guessed_format()
        .map_err(|error| FileError::io("failed to inspect image format", error))?
        .into_dimensions()
    {
        Ok(dimensions) => dimensions,
        Err(_) => return Ok(None),
    };
    if !valid_dimensions(width, height) {
        return Ok(None);
    }
    let mut reader = ImageReader::open(path)
        .map_err(|error| FileError::io("failed to open thumbnail source", error))?
        .with_guessed_format()
        .map_err(|error| FileError::io("failed to inspect image format", error))?;
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(32 * 1024 * 1024);
    limits.max_image_width = Some(width);
    limits.max_image_height = Some(height);
    reader.limits(limits);
    let decoded = match reader.decode() {
        Ok(image) => image,
        Err(_) => return Ok(None),
    };
    // Do not upscale a small source: the decoded-pixel budget must also bound
    // the intermediate output. Consume it when converting to RGBA.
    let thumbnail = decoded
        .thumbnail(dimension.min(width), dimension.min(height))
        .into_rgba8();
    let mut bytes = Vec::new();
    image::codecs::png::PngEncoder::new(&mut bytes).write_image(
        thumbnail.as_raw(),
        thumbnail.width(),
        thumbnail.height(),
        image::ExtendedColorType::Rgba8,
    )?;
    if bytes.len() > MAX_ENCODED_BYTES {
        return Ok(None);
    }
    Ok(Some(ImageThumbnail {
        bytes,
        media_type: "image/png".into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_and_dimension_admission_need_no_runtime() {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let directory = tempfile::tempdir().unwrap();
        FileShareService::load(directory.path()).unwrap();
        assert!(valid_dimensions(1920, 1080));
        assert!(!valid_dimensions(50_000, 50_000));
        assert!(!valid_dimensions(0, 50));
    }

    #[test]
    fn small_sources_are_never_upscaled_to_the_requested_bound() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("small.png");
        image::RgbaImage::new(32, 16).save(&path).unwrap();
        let thumbnail = build_image_thumbnail(&path, 4096).unwrap().unwrap();
        let decoded = image::load_from_memory(&thumbnail.bytes).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (32, 16));
    }

    #[tokio::test]
    async fn cached_thumbnail_bypasses_busy_content_budget_and_invalidates_on_change() {
        let config = tempfile::tempdir().unwrap();
        let shared = tempfile::tempdir().unwrap();
        let resources = Arc::new(arcrelay_content::ContentResources::new(1, 128));
        let service =
            FileShareService::load_with_resources(config.path(), resources.clone()).unwrap();
        let share = service.add_share(shared.path()).unwrap();
        let path = shared.path().join("sample.png");
        image::RgbImage::new(96, 64).save(&path).unwrap();
        let first = service
            .prepare_thumbnail(&share.id, "sample.png", 64, false)
            .await
            .unwrap()
            .unwrap();
        let held = resources.work(WORK_BYTES).await.unwrap();
        let cached = tokio::time::timeout(
            Duration::from_secs(1),
            service.prepare_thumbnail(&share.id, "sample.png", 64, false),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(first.bytes, cached.bytes);
        image::RgbImage::from_pixel(127, 65, image::Rgb([255, 0, 0]))
            .save(&path)
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(20),
            service.prepare_thumbnail(&share.id, "sample.png", 64, false)
        )
        .await
        .is_err());
        drop(held);
        assert_ne!(
            first.bytes,
            service
                .prepare_thumbnail(&share.id, "sample.png", 64, false)
                .await
                .unwrap()
                .unwrap()
                .bytes
        );
    }

    #[test]
    fn cache_obeys_total_bytes_and_entry_count() {
        let mut cache = ThumbnailCache::default();
        for index in 0..100 {
            cache.insert(
                index.to_string(),
                ImageThumbnail {
                    bytes: vec![0; 1024 * 1024],
                    media_type: "image/png".into(),
                },
            );
        }
        assert!(cache.bytes <= CACHE_BYTES);
        assert!(cache.entries.len() <= CACHE_ENTRIES);
        assert!(cache.get("0").is_none());
        assert!(cache.get("99").is_some());
    }
}
