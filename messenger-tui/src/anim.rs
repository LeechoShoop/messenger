use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct AnimState {
    pub start: Instant,
    pub duration: Duration,
    pub easing: fn(f32) -> f32,
    pub reduced_motion: bool,
}

impl AnimState {
    pub fn new(duration: Duration, easing: fn(f32) -> f32) -> Self {
        let reduced_motion = std::env::var("PRIMUS_REDUCED_MOTION").is_ok();
        Self {
            start: Instant::now(),
            duration,
            easing,
            reduced_motion,
        }
    }

    pub fn progress(&self) -> f32 {
        if self.reduced_motion {
            return 1.0;
        }
        let elapsed = self.start.elapsed();
        if elapsed >= self.duration {
            1.0
        } else {
            let t = elapsed.as_secs_f32() / self.duration.as_secs_f32();
            (self.easing)(t)
        }
    }
}

pub fn ease_out_quad(t: f32) -> f32 {
    1.0 - (1.0 - t) * (1.0 - t)
}

pub fn ease_in_out_sine(t: f32) -> f32 {
    -(f32::cos(std::f32::consts::PI * t) - 1.0) / 2.0
}

/// Returns a character from a spinner sequence based on elapsed time.
pub fn spinner_frame(start: Instant) -> &'static str {
    if std::env::var("PRIMUS_REDUCED_MOTION").is_ok() {
        return "…";
    }
    const FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let ms = start.elapsed().as_millis();
    let frame_idx = (ms / 80) as usize % FRAMES.len();
    FRAMES[frame_idx]
}
