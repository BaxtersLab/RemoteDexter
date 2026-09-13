//! Delta Engine implementation

use crate::types::{RawFrame, DirtyRect};

pub struct DeltaEngine {
    prev_hashes: Vec<u64>,
    grid_w: u32,
    grid_h: u32,
    screen_w: u32,
    screen_h: u32,
}

impl DeltaEngine {
    pub fn new(screen_w: u32, screen_h: u32) -> Self {
        let grid_w = (screen_w + 63) / 64;
        let grid_h = (screen_h + 63) / 64;
        let len = (grid_w * grid_h) as usize;
        Self {
            prev_hashes: vec![0; len],
            grid_w,
            grid_h,
            screen_w,
            screen_h,
        }
    }

    pub fn compute_bounding_box(&mut self, frame: &RawFrame) -> Option<DirtyRect> {
        use ahash::AHasher;
        use std::hash::{Hash, Hasher};

        let mut min_x = u32::MAX;
        let mut min_y = u32::MAX;
        let mut max_x = 0u32;
        let mut max_y = 0u32;
        let mut any_dirty = false;

        let stride = frame.width * 4; // assuming RGBA/BGRA

        for gy in 0..self.grid_h {
            for gx in 0..self.grid_w {
                let idx = (gy * self.grid_w + gx) as usize;

                let x0 = gx * 64;
                let y0 = gy * 64;
                if x0 >= frame.width || y0 >= frame.height {
                    continue;
                }

                let x1 = ((x0 + 64).min(frame.width)) as usize;
                let y1 = ((y0 + 64).min(frame.height)) as usize;

                let mut hasher = AHasher::default();

                for y in y0 as usize..y1 {
                    let row_start = (y as u32 * stride) as usize;
                    let start = row_start + (x0 * 4) as usize;
                    let end = row_start + (x1 * 4) as usize;
                    frame.data[start..end].hash(&mut hasher);
                }

                let h = hasher.finish();
                if h != self.prev_hashes[idx] {
                    self.prev_hashes[idx] = h;
                    any_dirty = true;

                    let block_x0 = x0;
                    let block_y0 = y0;
                    let block_x1 = x1 as u32;
                    let block_y1 = y1 as u32;

                    if block_x0 < min_x { min_x = block_x0; }
                    if block_y0 < min_y { min_y = block_y0; }
                    if block_x1 > max_x { max_x = block_x1; }
                    if block_y1 > max_y { max_y = block_y1; }
                }
            }
        }

        if !any_dirty {
            return None;
        }

        let bw = max_x - min_x;
        let bh = max_y - min_y;
        let bbox_area = bw as u64 * bh as u64;
        let screen_area = self.screen_w as u64 * self.screen_h as u64;

        if bbox_area as f64 > screen_area as f64 * 0.60 {
            None // signal full-frame
        } else {
            Some(DirtyRect {
                x: min_x,
                y: min_y,
                w: bw,
                h: bh,
            })
        }
    }
}