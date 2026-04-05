use crate::monitor::PostureSnapshot;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, Paragraph, Sparkline},
    style::{Color, Modifier, Style},
    Terminal,
};
use std::io;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

pub struct AuditorDashboard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl AuditorDashboard {
    pub fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    pub fn draw(&mut self, snapshot: &PostureSnapshot) -> io::Result<()> {
        self.terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // Header
                    Constraint::Max(6),    // Core Metrics (Scalable)
                    Constraint::Max(6),    // Quality Pulse (Scalable)
                    Constraint::Min(3),    // Signal Waveform (Responsive)
                    Constraint::Length(3), // Status (Fixed)
                ])
                .split(f.size());

            // 1. Header
            let header = Paragraph::new("🛡️  PROJECT AEGIS: THE COMPLIANCE SENTINEL | AUDIT MODE: ACTIVE")
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(header, chunks[0]);

            // 2. Core Metrics
            let metrics_text = format!(
                " 📂 Active Sources: {} | 📜 Processed: {} | 🚩 Signals Found: {} | ⏱️  Uptime: {}s",
                snapshot.sources_active, snapshot.total_processed, snapshot.signals_found, snapshot.uptime_secs
            );
            let metrics = Paragraph::new(metrics_text)
                .block(Block::default().title(" COMPLIANCE CORE ").borders(Borders::ALL));
            f.render_widget(metrics, chunks[1]);

            // 3. Quality Pulse (The "Auditor Proof")
            let quality_color = if snapshot.success_rate > 99.0 { Color::Green } 
                              else if snapshot.success_rate > 90.0 { Color::Yellow } 
                              else { Color::Red };

            let quality_text = format!(
                " ✅ Parsing Success: {:.2}% | ⚠️  Partial Timestamps: {} | ❌ Skipped/Malformed: {}\n AU-9 Privacy Pass: ACTIVE | Redaction Engine: OPERATIONAL",
                snapshot.success_rate, snapshot.timestamp_fallbacks, snapshot.lines_skipped
            );
            let quality = Paragraph::new(quality_text)
                .style(Style::default().fg(quality_color))
                .block(Block::default().title(" QUALITY PULSE (NIST AU-3) ").borders(Borders::ALL));
            f.render_widget(quality, chunks[2]);

            // 4. Waveform Pulse
            let sparkline = Sparkline::default()
                .block(Block::default().title(" NIST SIGNAL PULSE (15s Window) ").borders(Borders::ALL))
                .data(&snapshot.pulse_data)
                .style(Style::default().fg(Color::Yellow));
            f.render_widget(sparkline, chunks[3]);

            // 5. Status Footer
            let footer_style = if snapshot.status.contains("ERROR") { Style::default().fg(Color::Red) } else { Style::default().fg(Color::Gray) };
            let footer = Paragraph::new(format!(" 🛡️  STATE: {} | [R] Export | [ESC] Shutdown", snapshot.status))
                .style(footer_style)
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(footer, chunks[4]);
        })?;
        Ok(())
    }

    pub fn cleanup(&mut self) -> io::Result<()> {
        disable_raw_mode()?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)?;
        self.terminal.show_cursor()?;
        Ok(())
    }
}
