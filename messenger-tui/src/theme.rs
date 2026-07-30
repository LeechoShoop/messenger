// =============================================================================
// messenger-tui/src/theme.rs — Color theme and style constants
//
// Centralises all palette decisions. Provides a struct that can be loaded
// from a JSON file.
// =============================================================================

use ratatui::style::{Color, Modifier, Style};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Theme {
    pub bg: (u8, u8, u8),
    pub surface: (u8, u8, u8),
    pub surface2: (u8, u8, u8),
    pub border: (u8, u8, u8),
    pub border_focus: (u8, u8, u8),

    pub accent: (u8, u8, u8),
    pub accent2: (u8, u8, u8),

    pub fg: (u8, u8, u8),
    pub fg_dim: (u8, u8, u8),
    pub fg_highlight: (u8, u8, u8),

    pub timestamp: (u8, u8, u8),
    pub status_sent: (u8, u8, u8),
    pub status_ok: (u8, u8, u8),
    pub status_err: (u8, u8, u8),

    pub peer_active: (u8, u8, u8),
    pub peer_known: (u8, u8, u8),

    pub my_msg: (u8, u8, u8),
    pub their_msg: (u8, u8, u8),
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark_hacker()
    }
}

impl Theme {
    pub fn dark_hacker() -> Self {
        Self {
            bg: (15, 17, 23),
            surface: (22, 27, 34),
            surface2: (30, 36, 46),
            border: (48, 54, 68),
            border_focus: (82, 175, 200),
            accent: (82, 175, 200),
            accent2: (52, 152, 175),
            fg: (210, 215, 225),
            fg_dim: (110, 120, 140),
            fg_highlight: (255, 255, 255),
            timestamp: (190, 150, 80),
            status_sent: (130, 140, 160),
            status_ok: (80, 200, 130),
            status_err: (210, 70, 90),
            peer_active: (80, 200, 130),
            peer_known: (130, 140, 160),
            my_msg: (82, 175, 200),
            their_msg: (210, 215, 225),
        }
    }

    pub fn muted_forest() -> Self {
        Self {
            bg: (20, 24, 20),
            surface: (28, 33, 28),
            surface2: (38, 44, 38),
            border: (55, 65, 55),
            border_focus: (120, 180, 120),
            accent: (120, 180, 120),
            accent2: (90, 140, 90),
            fg: (200, 210, 200),
            fg_dim: (130, 140, 130),
            fg_highlight: (240, 255, 240),
            timestamp: (180, 160, 100),
            status_sent: (140, 150, 140),
            status_ok: (100, 190, 100),
            status_err: (200, 80, 80),
            peer_active: (100, 190, 100),
            peer_known: (140, 150, 140),
            my_msg: (120, 180, 120),
            their_msg: (200, 210, 200),
        }
    }

    pub fn load_or_default(path: &Path) -> Self {
        if path.exists() {
            if let Ok(contents) = std::fs::read_to_string(path) {
                if let Ok(theme) = serde_json::from_str(&contents) {
                    return theme;
                }
            }
        }
        
        let default_theme = Self::dark_hacker();
        // Try to save the default if the file is missing or invalid
        if let Ok(json) = serde_json::to_string_pretty(&default_theme) {
            let _ = std::fs::write(path, json);
        }
        
        default_theme
    }

    // Helpers to get ratatui colors
    pub fn get_bg(&self) -> Color { Color::Rgb(self.bg.0, self.bg.1, self.bg.2) }
    pub fn get_surface(&self) -> Color { Color::Rgb(self.surface.0, self.surface.1, self.surface.2) }
    pub fn get_surface2(&self) -> Color { Color::Rgb(self.surface2.0, self.surface2.1, self.surface2.2) }
    pub fn get_border(&self) -> Color { Color::Rgb(self.border.0, self.border.1, self.border.2) }
    pub fn get_border_focus(&self) -> Color { Color::Rgb(self.border_focus.0, self.border_focus.1, self.border_focus.2) }
    pub fn get_accent(&self) -> Color { Color::Rgb(self.accent.0, self.accent.1, self.accent.2) }
    pub fn get_fg(&self) -> Color { Color::Rgb(self.fg.0, self.fg.1, self.fg.2) }
    pub fn get_fg_dim(&self) -> Color { Color::Rgb(self.fg_dim.0, self.fg_dim.1, self.fg_dim.2) }
    pub fn get_fg_highlight(&self) -> Color { Color::Rgb(self.fg_highlight.0, self.fg_highlight.1, self.fg_highlight.2) }
    pub fn get_timestamp(&self) -> Color { Color::Rgb(self.timestamp.0, self.timestamp.1, self.timestamp.2) }
    pub fn get_status_sent(&self) -> Color { Color::Rgb(self.status_sent.0, self.status_sent.1, self.status_sent.2) }
    pub fn get_status_ok(&self) -> Color { Color::Rgb(self.status_ok.0, self.status_ok.1, self.status_ok.2) }
    pub fn get_status_err(&self) -> Color { Color::Rgb(self.status_err.0, self.status_err.1, self.status_err.2) }
    pub fn get_peer_active(&self) -> Color { Color::Rgb(self.peer_active.0, self.peer_active.1, self.peer_active.2) }
    pub fn get_peer_known(&self) -> Color { Color::Rgb(self.peer_known.0, self.peer_known.1, self.peer_known.2) }
    pub fn get_my_msg(&self) -> Color { Color::Rgb(self.my_msg.0, self.my_msg.1, self.my_msg.2) }
    pub fn get_their_msg(&self) -> Color { Color::Rgb(self.their_msg.0, self.their_msg.1, self.their_msg.2) }

    // Composed styles
    pub fn border_style(&self) -> Style { Style::default().fg(self.get_border()) }
    pub fn border_focused_style(&self) -> Style { Style::default().fg(self.get_border_focus()) }
    pub fn title_style(&self) -> Style { Style::default().fg(self.get_accent()).add_modifier(Modifier::BOLD) }
    pub fn body_style(&self) -> Style { Style::default().fg(self.get_fg()).bg(self.get_surface()) }
    pub fn dim_style(&self) -> Style { Style::default().fg(self.get_fg_dim()) }
    pub fn highlight_style(&self) -> Style { Style::default().fg(self.get_fg_highlight()).add_modifier(Modifier::BOLD) }
    pub fn input_style(&self) -> Style { Style::default().fg(self.get_fg()).bg(self.get_surface2()) }
    pub fn cursor_style(&self) -> Style { Style::default().fg(self.get_bg()).bg(self.get_accent()) }
    pub fn status_bar_style(&self) -> Style { Style::default().fg(self.get_fg_dim()).bg(self.get_surface2()) }
    pub fn peer_active_style(&self) -> Style { Style::default().fg(self.get_peer_active()).add_modifier(Modifier::BOLD) }
    pub fn peer_known_style(&self) -> Style { Style::default().fg(self.get_peer_known()) }
    pub fn timestamp_style(&self) -> Style { Style::default().fg(self.get_timestamp()) }
    pub fn msg_mine_style(&self) -> Style { Style::default().fg(self.get_my_msg()) }
    pub fn msg_theirs_style(&self) -> Style { Style::default().fg(self.get_their_msg()) }
    pub fn status_sent_style(&self) -> Style { Style::default().fg(self.get_status_sent()) }
    pub fn status_delivered_style(&self) -> Style { Style::default().fg(self.get_status_ok()) }
    pub fn status_failed_style(&self) -> Style { Style::default().fg(self.get_status_err()) }
}
