// =============================================================================
// messenger-tui/src/ui.rs — Ratatui layout and rendering
//
// Renders the layout:
//
//   ┌──────────────┬──────────────────────────────────────────┐
//   │  PEERS       │  TABS                                    │
//   │  (sidebar)   ├──────────────────────────────────────────┤
//   │              │  CHAT                                    │
//   │              │  (conversation history)                  │
//   │              │                                          │
//   │              ├──────────────────────────────────────────┤
//   │              │  INPUT + STATUS BAR                      │
//   └──────────────┴──────────────────────────────────────────┘
//
// Layout proportions (horizontal split):
//   • Peer sidebar: dynamic width based on app.sidebar_width, rest goes to chat.
// =============================================================================

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect, Alignment};

use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph, Wrap, Clear, Tabs};

use crate::app::{App, ChatStatus, Focus};

/// Top-level render function. Called by the event loop on every tick.
pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // ── Horizontal split: sidebar | right pane ────────────────────────────────
    let h_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(app.sidebar_width), // dynamic peer sidebar
            Constraint::Min(40),                   // chat + input
        ])
        .split(area);

    // ── Right pane vertical split: tabs | chat | input bar | status bar ───────
    let v_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),            // tabs
            Constraint::Min(5),               // chat history
            Constraint::Length(3),            // input field
            Constraint::Length(1),            // status bar
        ])
        .split(h_chunks[1]);

    render_peer_list(frame, app, h_chunks[0]);
    render_tabs(frame, app, v_chunks[0]);
    render_chat(frame, app, v_chunks[1]);
    render_input(frame, app, v_chunks[2]);
    render_status(frame, app, v_chunks[3]);

    if app.help_open {
        render_help(frame, app, area);
    }
}

// ── Peer sidebar ──────────────────────────────────────────────────────────────

fn render_peer_list(frame: &mut Frame, app: &App, area: Rect) {
    let focused = app.focus == Focus::PeerList;

    let border_style = if focused {
        if std::env::var("PRIMUS_REDUCED_MOTION").is_ok() {
            app.theme.border_focused_style()
        } else {
            let elapsed = app.app_start.elapsed().as_secs_f32();
            let t = (elapsed * 2.0).sin() * 0.5 + 0.5; // 0.0 to 1.0
            let t = crate::anim::ease_in_out_sine(t);
            let color = interpolate_color(app.theme.get_border_focus(), app.theme.get_border(), t * 0.4);
            ratatui::style::Style::default().fg(color)
        }
    } else {
        app.theme.border_style()
    };

    let block = Block::default()
        .title(Span::styled(" ◈ Peers ", app.theme.title_style()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style)
        .style(app.theme.body_style());

    if app.peers.is_empty() {
        let placeholder = Paragraph::new(Text::from(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Discovering…",
                app.theme.dim_style(),
            )),
        ]))
        .block(block);
        frame.render_widget(placeholder, area);
        return;
    }

    let items: Vec<ListItem> = app
        .peers
        .iter()
        .enumerate()
        .map(|(i, peer)| {
            let is_selected = app.selected_peer == Some(i);
            let dot = if peer.connected { 
                "● ".to_string() 
            } else if peer.dialing {
                format!("{} ", crate::anim::spinner_frame(app.app_start))
            } else { 
                "○ ".to_string() 
            };
            let dot_style = if peer.connected {
                app.theme.peer_active_style()
            } else {
                app.theme.peer_known_style()
            };

            let id_hex = hex::encode(&peer.node_id[..4]);
            let id_str = format!("{id_hex}…");
            let _addr_str = format!(" {}", peer.addr);

            let name_style = if is_selected {
                app.theme.highlight_style()
            } else {
                app.theme.body_style()
            };

            ListItem::new(Line::from(vec![
                Span::styled(dot, dot_style),
                Span::styled(id_str, name_style),
            ]))
            .style(if is_selected {
                app.theme.body_style().bg(app.theme.get_surface2())
            } else {
                app.theme.body_style()
            })
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(app.selected_peer);

    let list = List::new(items)
        .block(block)
        .highlight_style(app.theme.highlight_style().bg(app.theme.get_surface2()));

    frame.render_stateful_widget(list, area, &mut list_state);
}

// ── Tab Bar ───────────────────────────────────────────────────────────────────

fn render_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(app.theme.border_style())
        .style(app.theme.body_style());

    if app.open_tabs.is_empty() {
        frame.render_widget(block, area);
        return;
    }

    let titles: Vec<Line> = app.open_tabs.iter().map(|id| {
        let hex = hex::encode(&id[..4]);
        Line::from(format!(" {hex}… "))
    }).collect();

    let tabs = Tabs::new(titles)
        .block(block)
        .select(app.active_tab_index)
        .style(app.theme.dim_style())
        .highlight_style(app.theme.highlight_style().bg(app.theme.get_surface2()));

    frame.render_widget(tabs, area);
}

// ── Chat pane ─────────────────────────────────────────────────────────────────

fn render_chat(frame: &mut Frame, app: &App, area: Rect) {
    let title = match app.open_tabs.get(app.active_tab_index) {
        Some(peer_id) => format!(" ◈ {} ", hex::encode(&peer_id[..6])),
        None => " ◈ Select a peer to chat ".to_string(),
    };

    let block = Block::default()
        .title(Span::styled(title, app.theme.title_style()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(app.theme.border_style())
        .style(app.theme.body_style());

    if app.messages.is_empty() {
        let hint = match app.open_tabs.get(app.active_tab_index) {
            None => "← Select a peer to start chatting",
            Some(_) => "No messages yet. Type below and press Enter.",
        };
        let placeholder = Paragraph::new(Text::from(vec![
            Line::from(""),
            Line::from(Span::styled(
                format!("  {hint}"),
                app.theme.dim_style(),
            )),
        ]))
        .block(block);
        frame.render_widget(placeholder, area);
        return;
    }

    // Build lines from chat history (most-recent at the bottom).
    let mut lines: Vec<Line> = Vec::with_capacity(app.messages.len() * 2);
    for msg in &app.messages {
        let time = format_time(msg.sent_at);
        let sender_hex = hex::encode(&msg.sender_id[..4]);

        let mut progress = 1.0;
        if let Some(anim) = &msg.anim {
            progress = anim.progress();
        }

        // Slight upward slide: push down by inserting empty lines above if progress < 1.0
        if progress < 1.0 {
            let shift = (1.0 - progress) * 1.2;
            if shift > 0.5 {
                lines.push(Line::from(""));
            }
        }

        let bg_color = app.theme.get_surface();
        
        if msg.is_mine {
            // Right-aligned style: timestamp + status + "You"
            let status_str = match msg.status {
                ChatStatus::Sent      => "⟳",
                ChatStatus::Delivered => "✓",
                ChatStatus::Failed    => "✗",
            };
            let mut status_style = match msg.status {
                ChatStatus::Sent      => app.theme.status_sent_style(),
                ChatStatus::Delivered => app.theme.status_delivered_style(),
                ChatStatus::Failed    => app.theme.status_failed_style(),
            };
            let mut ts_style = app.theme.timestamp_style();
            let mut mine_style = app.theme.msg_mine_style();
            
            if progress < 1.0 {
                if let Some(c) = status_style.fg { status_style.fg = Some(interpolate_color(bg_color, c, progress)); }
                if let Some(c) = ts_style.fg { ts_style.fg = Some(interpolate_color(bg_color, c, progress)); }
                if let Some(c) = mine_style.fg { mine_style.fg = Some(interpolate_color(bg_color, c, progress)); }
            }

            lines.push(Line::from(vec![
                Span::styled(format!("  [{time}] "), ts_style),
                Span::styled("You ", mine_style),
                Span::styled(status_str, status_style),
            ]));
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(&*msg.text, mine_style),
            ]));
        } else {
            let mut ts_style = app.theme.timestamp_style();
            let mut known_style = app.theme.peer_known_style();
            let mut theirs_style = app.theme.msg_theirs_style();
            
            if progress < 1.0 {
                if let Some(c) = ts_style.fg { ts_style.fg = Some(interpolate_color(bg_color, c, progress)); }
                if let Some(c) = known_style.fg { known_style.fg = Some(interpolate_color(bg_color, c, progress)); }
                if let Some(c) = theirs_style.fg { theirs_style.fg = Some(interpolate_color(bg_color, c, progress)); }
            }

            lines.push(Line::from(vec![
                Span::styled(format!("  [{time}] "), ts_style),
                Span::styled(format!("{sender_hex}…"), known_style),
            ]));
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(&*msg.text, theirs_style),
            ]));
        }

        lines.push(Line::from("")); // spacing between bubbles
    }

    let total_lines = lines.len() as u16;
    let visible_lines = area.height.saturating_sub(2); // subtract borders
    let scroll = if total_lines > visible_lines {
        total_lines - visible_lines - app.chat_scroll
    } else {
        0
    };

    let chat = Paragraph::new(Text::from(lines))
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));

    frame.render_widget(chat, area);
}

// ── Input field ───────────────────────────────────────────────────────────────

fn render_input(frame: &mut Frame, app: &App, area: Rect) {
    let focused = app.focus == Focus::Input;

    let border_style = if focused {
        if std::env::var("PRIMUS_REDUCED_MOTION").is_ok() {
            app.theme.border_focused_style()
        } else {
            let elapsed = app.app_start.elapsed().as_secs_f32();
            let t = (elapsed * 2.0).sin() * 0.5 + 0.5; // 0.0 to 1.0
            let t = crate::anim::ease_in_out_sine(t);
            let color = interpolate_color(app.theme.get_border_focus(), app.theme.get_border(), t * 0.4);
            ratatui::style::Style::default().fg(color)
        }
    } else {
        app.theme.border_style()
    };

    let prompt = match app.open_tabs.get(app.active_tab_index) {
        Some(_) => " ▶ ",
        None    => " ▷ ", // dimmed arrow when no active tab
    };

    // Build the displayed text. Ratatui doesn't manage a cursor natively for
    // Paragraph — we simulate it by splitting the input at the cursor position
    // and rendering the character under the cursor with a reverse-video style.
    let before: &str = &app.input[..app.input_cursor];
    let at_cursor: &str = if app.input_cursor < app.input.len() {
        let ch_end = app.input[app.input_cursor..]
            .char_indices()
            .nth(1)
            .map(|(i, _)| app.input_cursor + i)
            .unwrap_or(app.input.len());
        &app.input[app.input_cursor..ch_end]
    } else {
        " " // phantom cursor at end
    };
    let after: &str = if app.input_cursor < app.input.len() {
        let ch_end = app.input[app.input_cursor..]
            .char_indices()
            .nth(1)
            .map(|(i, _)| app.input_cursor + i)
            .unwrap_or(app.input.len());
        &app.input[ch_end..]
    } else {
        ""
    };

    let input_line = if focused {
        Line::from(vec![
            Span::styled(prompt, app.theme.msg_mine_style()),
            Span::styled(before, app.theme.input_style()),
            Span::styled(at_cursor, app.theme.cursor_style()),
            Span::styled(after, app.theme.input_style()),
        ])
    } else {
        Line::from(vec![
            Span::styled(prompt, app.theme.dim_style()),
            Span::styled(&*app.input, app.theme.dim_style()),
        ])
    };

    let input_widget = Paragraph::new(Text::from(vec![input_line]))
        .block(
            Block::default()
                .title(Span::styled(" ◈ Message ", app.theme.title_style()))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(border_style)
                .style(app.theme.input_style()),
        );

    frame.render_widget(input_widget, area);
}

// ── Status bar ────────────────────────────────────────────────────────────────

fn render_status(frame: &mut Frame, app: &App, area: Rect) {
    let keys = "[?] help  [Tab] focus  [↑↓] peer  [Enter] send  [Esc/q] quit";
    let status_text = if app.bootstrap_running {
        format!("{} | Bootstrap self-lookup {}", app.status, crate::anim::spinner_frame(app.app_start))
    } else {
        app.status.clone()
    };
    
    let line = Line::from(vec![
        Span::styled(" ", app.theme.status_bar_style()),
        Span::styled(status_text, app.theme.dim_style()),
        Span::styled("  │  ", app.theme.dim_style()),
        Span::styled(keys, app.theme.dim_style()),
    ]);
    let bar = Paragraph::new(Text::from(vec![line])).style(app.theme.status_bar_style());
    frame.render_widget(bar, area);
}

// ── Help Overlay ──────────────────────────────────────────────────────────────
fn render_help(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Span::styled(" ◈ Keybindings (press ? to close) ", app.theme.title_style()))
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(app.theme.border_focused_style())
        .style(app.theme.body_style());

    let lines = vec![
        Line::from(vec![Span::styled(" Global:", app.theme.highlight_style())]),
        Line::from(vec![Span::raw("  [?]          Toggle this help overlay")]),
        Line::from(vec![Span::raw("  [Tab]        Cycle focus (Input ↔ Peers)")]),
        Line::from(vec![Span::raw("  [Alt+Left/Right] Switch active tabs")]),
        Line::from(vec![Span::raw("  [Alt+W]      Close active tab")]),
        Line::from(vec![Span::raw("  [Shift+Left/Right] Resize peer sidebar")]),
        Line::from(vec![Span::raw("  [Ctrl+C, q]  Quit application")]),
        Line::from(vec![Span::raw("")]),
        Line::from(vec![Span::styled(" Peers Pane:", app.theme.highlight_style())]),
        Line::from(vec![Span::raw("  [↑ / ↓]      Select previous / next peer")]),
        Line::from(vec![Span::raw("  [Enter]      Open chat tab with peer")]),
        Line::from(vec![Span::raw("")]),
        Line::from(vec![Span::styled(" Chat Pane:", app.theme.highlight_style())]),
        Line::from(vec![Span::raw("  [↑ / ↓]      Scroll chat history (when Input focused)")]),
        Line::from(vec![Span::raw("  [Enter]      Send message")]),
    ];

    let content = Paragraph::new(Text::from(lines))
        .block(block)
        .alignment(Alignment::Left);

    let popup_area = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(60),
            Constraint::Percentage(20),
        ])
        .split(area)[1];

    let popup_area = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(60),
            Constraint::Percentage(20),
        ])
        .split(popup_area)[1];

    frame.render_widget(Clear, popup_area); // clear background
    frame.render_widget(content, popup_area);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn format_time(unix_secs: u64) -> String {
    let s = unix_secs % 86400;
    let h = s / 3600;
    let m = (s % 3600) / 60;
    format!("{h:02}:{m:02}")
}

fn interpolate_color(c1: ratatui::style::Color, c2: ratatui::style::Color, t: f32) -> ratatui::style::Color {
    if let (ratatui::style::Color::Rgb(r1, g1, b1), ratatui::style::Color::Rgb(r2, g2, b2)) = (c1, c2) {
        ratatui::style::Color::Rgb(
            (r1 as f32 + (r2 as f32 - r1 as f32) * t) as u8,
            (g1 as f32 + (g2 as f32 - g1 as f32) * t) as u8,
            (b1 as f32 + (b2 as f32 - b1 as f32) * t) as u8,
        )
    } else {
        c2
    }
}
