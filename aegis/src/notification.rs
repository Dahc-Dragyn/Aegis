use winrt_notification::{Duration, Sound, Toast};
use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Global cooldown for notifications (5 seconds) to prevent system spam.
static LAST_NOTIFICATION: AtomicU64 = AtomicU64::new(0);
const COOLDOWN_SECS: u64 = 5;

pub struct NotificationEngine;

impl NotificationEngine {
    fn can_notify() -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let last = LAST_NOTIFICATION.load(Ordering::Relaxed);
        
        if now >= last + COOLDOWN_SECS {
            LAST_NOTIFICATION.store(now, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Sends a high-fidelity Windows 11 Toast notification for a single security breach.
    pub fn send_alert(control_id: &str, description: &str) -> Result<()> {
        if !Self::can_notify() {
            return Ok(());
        }

        Toast::new(Toast::POWERSHELL_APP_ID)
            .title("🛡️ Aegis Sentinel: Critical Signal")
            .text1(control_id)
            .text2(description)
            .sound(Some(Sound::Reminder))
            .duration(Duration::Long)
            .show()?;
        Ok(())
    }

    /// Sends a summary notification for multiple threats detected in a single batch.
    pub fn send_summary_alert(count: usize) -> Result<()> {
        if !Self::can_notify() {
            return Ok(());
        }

        Toast::new(Toast::POWERSHELL_APP_ID)
            .title("🚨 Aegis Sentinel: Multi-Signal Cluster")
            .text1(&format!("Detected {} security violations in the recent batch.", count))
            .text2("Manual audit check recommended in Dashboard.")
            .sound(Some(Sound::Reminder))
            .duration(Duration::Long)
            .show()?;
        Ok(())
    }
}
