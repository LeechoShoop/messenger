// =============================================================================
// messenger-tui/src/terminal.rs — Terminal setup, teardown, and panic hook
//
// Responsibilities:
//   • Enable raw mode + alternate screen on entry.
//   • Restore the terminal (leave alternate screen, disable raw mode) on exit
//     OR on panic — so a crash never leaves the shell in raw mode.
//   • Expose a thin `Tui` wrapper that owns a `CrosstermBackend<Stdout>` and
//     delegates draw calls to ratatui.
//
// The panic hook is installed once via `install_panic_hook()`, which must be
// called BEFORE the Tui is initialized (so the hook is in place by the time
// anything could panic during setup). The hook captures the original hook and
// calls it after restoring the terminal, so backtraces etc. still print.
// =============================================================================

use std::io::{self, Stdout};
use std::panic;

use anyhow::Result;
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

/// Owned terminal handle. Drop to restore the terminal to its original state.
///
/// Constructed via `Tui::init()`. On `Drop`, calls `restore()` so the shell
/// is left clean even if the caller exits via `?` early.
pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Tui {
    /// Enable raw mode + alternate screen, then construct a `Tui`.
    ///
    /// Must be called after `install_panic_hook()` so a panic during
    /// initialization is still handled correctly.
    pub fn init() -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    /// Restore raw mode and alternate screen.
    ///
    /// Idempotent — safe to call multiple times (subsequent calls after the
    /// first may return errors from crossterm, which are silently ignored here
    /// since there's nothing useful to do at teardown time other than try).
    pub fn restore() {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }

    /// Delegate to the underlying `Terminal::draw`.
    pub fn draw<F>(&mut self, f: F) -> Result<ratatui::CompletedFrame<'_>>
    where
        F: FnOnce(&mut ratatui::Frame),
    {
        Ok(self.terminal.draw(f)?)
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        Self::restore();
    }
}

/// Install a panic hook that restores the terminal before propagating the
/// panic. Must be called exactly once at program startup, before `Tui::init`.
///
/// Captures the *current* hook (which may itself be a previous hook, e.g.
/// from `color_eyre`) so that backtraces / custom panic messages still fire
/// after the terminal is restored.
pub fn install_panic_hook() {
    let original = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        // Attempt to restore the terminal first. If we panic before Tui is
        // initialised this is a no-op (crossterm's raw-mode check fails
        // gracefully).
        Tui::restore();
        original(info);
    }));
}
