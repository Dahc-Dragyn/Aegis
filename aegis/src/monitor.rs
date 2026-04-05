use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;
use std::collections::VecDeque;
use std::sync::Mutex;
use crate::models::ParsingQuality;

pub struct PostureMonitor {
    pub total_processed: AtomicU64,
    pub signals_found: AtomicU64,
    pub sources_active: AtomicUsize,
    pub start_time: Instant,
    
    // Quality Pulse Metrics (Audit Requirements)
    pub lines_skipped: AtomicU64,
    pub timestamp_fallbacks: AtomicU64,
    
    status_message: Mutex<String>,
    pulse_history: Mutex<VecDeque<u64>>,
    last_count: AtomicU64,
}

pub struct PostureSnapshot {
    pub total_processed: u64,
    pub signals_found: u64,
    pub sources_active: usize,
    pub uptime_secs: u64,
    pub eps: u64,
    pub pulse_data: Vec<u64>,
    pub status: String,
    
    // Quality Metrics for Dashboard
    pub lines_skipped: u64,
    pub timestamp_fallbacks: u64,
    pub success_rate: f64,
}

impl Default for PostureMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl PostureMonitor {
    pub fn new() -> Self {
        Self {
            total_processed: AtomicU64::new(0),
            signals_found: AtomicU64::new(0),
            sources_active: AtomicUsize::new(0),
            start_time: Instant::now(),
            lines_skipped: AtomicU64::new(0),
            timestamp_fallbacks: AtomicU64::new(0),
            status_message: Mutex::new("Sentinel Live".to_string()),
            pulse_history: Mutex::new(VecDeque::from(vec![0; 60])),
            last_count: AtomicU64::new(0),
        }
    }

    pub fn record_quality(&self, quality: &ParsingQuality) {
        match quality {
            ParsingQuality::Success => { self.total_processed.fetch_add(1, Ordering::Relaxed); },
            ParsingQuality::PartialTimestamp => {
                self.total_processed.fetch_add(1, Ordering::Relaxed);
                self.timestamp_fallbacks.fetch_add(1, Ordering::Relaxed);
            },
            ParsingQuality::Malformed => {
                self.lines_skipped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn increment_signals(&self, count: u64) {
        self.signals_found.fetch_add(count, Ordering::Relaxed);
    }

    pub fn increment_sources(&self, count: usize) {
        self.sources_active.fetch_add(count, Ordering::Relaxed);
    }

    pub fn set_status(&self, msg: String) {
        let mut status = self.status_message.lock().unwrap();
        *status = msg;
    }

    pub fn mark_caught_up(&self) {
        let mut status = self.status_message.lock().unwrap();
        *status = "🏁 Catch-up Complete. Tailing...".to_string();
    }

    pub fn tick(&self) {
        let current = self.total_processed.load(Ordering::Relaxed);
        let last = self.last_count.swap(current, Ordering::Relaxed);
        let processed_this_tick = current.saturating_sub(last);

        let mut history = self.pulse_history.lock().unwrap();
        history.push_back(processed_this_tick);
        if history.len() > 60 {
            history.pop_front();
        }
    }

    pub fn get_snapshot(&self) -> PostureSnapshot {
        let total = self.total_processed.load(Ordering::Relaxed);
        let skipped = self.lines_skipped.load(Ordering::Relaxed);
        let uptime = self.start_time.elapsed().as_secs();
        
        let eps = if uptime > 0 { total / uptime } else { 0 };
        let history = self.pulse_history.lock().unwrap();
        
        let success_rate = if (total + skipped) > 0 {
            (total as f64 / (total + skipped) as f64) * 100.0
        } else {
            100.0
        };

        PostureSnapshot {
            total_processed: total,
            signals_found: self.signals_found.load(Ordering::Relaxed),
            sources_active: self.sources_active.load(Ordering::Relaxed),
            uptime_secs: uptime,
            eps,
            pulse_data: history.iter().cloned().collect(),
            status: self.status_message.lock().unwrap().clone(),
            lines_skipped: skipped,
            timestamp_fallbacks: self.timestamp_fallbacks.load(Ordering::Relaxed),
            success_rate,
        }
    }
}
