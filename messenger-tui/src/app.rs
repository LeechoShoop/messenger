// =============================================================================
// messenger-tui/src/app.rs — Application state
//
// `App` is the single source of truth for the TUI's runtime state. It is
// constructed once, then passed mutably into the event loop and immutably into
// the renderer on each tick.
//
// HOW STATE EVOLVES (Hop 1 — static scaffold):
//   • `peers` and `messages` are empty Vecs — no data binding yet.
//   • `input` tracks the text the user is currently typing.
//   • `selected_peer` is the index into `peers` of the currently highlighted
//     peer in the sidebar (None until peers exist).
//   • `focus` decides which pane receives keyboard events.
//   • `status` is a one-line string shown in the status bar (node ID, error
//     messages, etc.).
//
// Hop 2 will wire `peers` to the live DHT, `messages` to the MessengerCore
// store, and add an mpsc channel for cross-task UI updates.
// =============================================================================

use messenger::dht::NodeID;
use crate::anim::AnimState;
use std::time::Instant;
use crate::theme::Theme;

/// Which UI pane currently owns keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Focus {
    #[default]
    Input,
    PeerList,
}

/// A lightweight peer entry for the sidebar.
/// Populated from `PrimusDHT::get_all_records()` in Hop 2.
#[derive(Debug, Clone)]
pub struct PeerEntry {
    pub node_id: NodeID,
    pub addr: std::net::SocketAddr,
    pub connected: bool, // true = active session
    pub dialing: bool,   // true = connect_to_peer in flight
}

/// A single chat bubble for display in the chat pane.
/// Populated from `MessengerCore`'s store in Hop 2.
#[derive(Debug, Clone)]
pub struct ChatLine {
    pub message_id: [u8; 32],
    pub sender_id: NodeID,
    pub text: String,
    pub sent_at: u64,       // unix epoch seconds
    pub is_mine: bool,
    pub status: ChatStatus,
    pub anim: Option<AnimState>,
}

#[allow(dead_code)] // variants populated in Hop 2 message binding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatStatus {
    Sent,
    Delivered,
    Failed,
}

/// Top-level TUI application state.
pub struct App {
    // ── Identity ──────────────────────────────────────────────────────────────
    pub local_node_id: NodeID,

    // ── Peer sidebar ─────────────────────────────────────────────────────────
    /// Known peers from the DHT. Updated by the event loop (Hop 2).
    pub peers: Vec<PeerEntry>,
    /// Index of the currently highlighted peer in the sidebar.
    pub selected_peer: Option<usize>,

    // ── Chat pane ─────────────────────────────────────────────────────────────
    /// Messages for the currently selected conversation. Rebuilt from the
    /// MessengerCore store whenever `selected_peer` changes (Hop 2).
    pub messages: Vec<ChatLine>,
    /// Scroll offset within the chat pane (lines from the bottom).
    pub chat_scroll: u16,

    // ── Input bar ────────────────────────────────────────────────────────────
    /// Text currently being composed by the user.
    pub input: String,
    /// Cursor position within `input` (byte index, left-of-character).
    pub input_cursor: usize,

    // ── Focus ────────────────────────────────────────────────────────────────
    pub focus: Focus,

    // ── Status bar ───────────────────────────────────────────────────────────
    /// One-line status string, e.g. "NodeID: abc123… | 3 peers".
    pub status: String,

    // ── Lifecycle ────────────────────────────────────────────────────────────
    /// Set to true by the event loop when the user requests exit.
    pub should_quit: bool,
    /// When the app started (used for continuous animations).
    pub app_start: Instant,
    /// Whether internet bootstrap self-lookup is currently running.
    pub bootstrap_running: bool,

    // ── Theming & UI State ───────────────────────────────────────────────────
    pub theme: Theme,
    pub help_open: bool,
    pub sidebar_width: u16,
    pub open_tabs: Vec<NodeID>,
    pub active_tab_index: usize,
}

impl App {
    pub fn new(local_node_id: NodeID, theme: Theme) -> Self {
        let id_short: String = hex::encode(&local_node_id[..4]);
        Self {
            local_node_id,
            peers: Vec::new(),
            selected_peer: None,
            messages: Vec::new(),
            chat_scroll: 0,
            input: String::new(),
            input_cursor: 0,
            focus: Focus::Input,
            status: format!("NodeID: {id_short}… | Starting up… (unencrypted)"),
            should_quit: false,
            app_start: Instant::now(),
            bootstrap_running: false,
            theme,
            help_open: false,
            sidebar_width: 26,
            open_tabs: Vec::new(),
            active_tab_index: 0,
        }
    }

    // ── Input helpers ─────────────────────────────────────────────────────────

    /// Insert `ch` at the current cursor position.
    pub fn insert_char(&mut self, ch: char) {
        self.input.insert(self.input_cursor, ch);
        self.input_cursor += ch.len_utf8();
    }

    /// Delete the character immediately before the cursor (backspace).
    pub fn backspace(&mut self) {
        if self.input_cursor == 0 {
            return;
        }
        // Find the start of the previous character (handles multi-byte).
        let prev = self.input[..self.input_cursor]
            .char_indices()
            .last()
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.input.remove(prev);
        self.input_cursor = prev;
    }

    /// Move cursor one character left.
    pub fn cursor_left(&mut self) {
        if self.input_cursor == 0 {
            return;
        }
        self.input_cursor = self.input[..self.input_cursor]
            .char_indices()
            .last()
            .map(|(i, _)| i)
            .unwrap_or(0);
    }

    /// Move cursor one character right.
    pub fn cursor_right(&mut self) {
        if self.input_cursor >= self.input.len() {
            return;
        }
        let ch = self.input[self.input_cursor..].chars().next().unwrap();
        self.input_cursor += ch.len_utf8();
    }

    /// Take the current input, reset to empty. Returns the composed string.
    pub fn take_input(&mut self) -> String {
        self.input_cursor = 0;
        std::mem::take(&mut self.input)
    }

    // ── Peer selection helpers ────────────────────────────────────────────────

    pub fn select_prev_peer(&mut self) {
        if self.peers.is_empty() {
            return;
        }
        self.selected_peer = Some(match self.selected_peer {
            None | Some(0) => self.peers.len() - 1,
            Some(i) => i - 1,
        });
    }

    pub fn select_next_peer(&mut self) {
        if self.peers.is_empty() {
            return;
        }
        self.selected_peer = Some(match self.selected_peer {
            None => 0,
            Some(i) => (i + 1) % self.peers.len(),
        });
    }

    pub fn selected_peer_entry(&self) -> Option<&PeerEntry> {
        self.selected_peer.and_then(|i| self.peers.get(i))
    }

    // ── Status helpers ────────────────────────────────────────────────────────

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
    }

    pub fn refresh_status(&mut self) {
        let id_short = hex::encode(&self.local_node_id[..4]);
        let peer_count = self.peers.len();
        let active = self.peers.iter().filter(|p| p.connected).count();
        self.status = format!(
            "NodeID: {id_short}… | peers: {peer_count} known, {active} connected | (unencrypted)"
        );
    }

    // ── Tab helpers ───────────────────────────────────────────────────────────

    pub fn open_tab(&mut self, peer_id: NodeID) {
        if let Some(idx) = self.open_tabs.iter().position(|id| id == &peer_id) {
            self.active_tab_index = idx;
        } else {
            self.open_tabs.push(peer_id);
            self.active_tab_index = self.open_tabs.len() - 1;
        }
        
        // Sync selected_peer to match the newly active tab if it's in the peer list
        if let Some(idx) = self.peers.iter().position(|p| p.node_id == peer_id) {
            self.selected_peer = Some(idx);
        }
    }

    pub fn close_tab(&mut self) {
        if self.open_tabs.is_empty() {
            return;
        }
        self.open_tabs.remove(self.active_tab_index);
        if self.active_tab_index >= self.open_tabs.len() {
            self.active_tab_index = self.open_tabs.len().saturating_sub(1);
        }
        self.sync_selected_peer_with_tab();
    }

    pub fn next_tab(&mut self) {
        if self.open_tabs.is_empty() {
            return;
        }
        self.active_tab_index = (self.active_tab_index + 1) % self.open_tabs.len();
        self.sync_selected_peer_with_tab();
    }

    pub fn prev_tab(&mut self) {
        if self.open_tabs.is_empty() {
            return;
        }
        self.active_tab_index = match self.active_tab_index {
            0 => self.open_tabs.len() - 1,
            i => i - 1,
        };
        self.sync_selected_peer_with_tab();
    }

    fn sync_selected_peer_with_tab(&mut self) {
        if let Some(peer_id) = self.open_tabs.get(self.active_tab_index) {
            if let Some(idx) = self.peers.iter().position(|p| p.node_id == *peer_id) {
                self.selected_peer = Some(idx);
            } else {
                self.selected_peer = None;
            }
        } else {
            self.selected_peer = None;
        }
    }
}
