//! Terminal handling module
//!
//! This module manages the local terminal state, including:
//! - Enabling/disabling raw mode (required to capture all input)
//! - Reading keyboard events
//! - Handling terminal resize events

use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    terminal::{self, disable_raw_mode, enable_raw_mode},
};
use std::io::{self, Write};
use std::time::Duration;

/// Guard that ensures raw mode is disabled when dropped
///
/// Raw mode is a terminal state where:
/// - Input is not line-buffered (we get each keypress immediately)
/// - Special keys like Ctrl+C are not handled by the terminal
/// - We need to handle everything ourselves
///
/// This guard pattern ensures we always restore normal terminal state,
/// even if the program panics.
pub struct RawModeGuard {
    _private: (), // Prevents construction outside this module
}

impl RawModeGuard {
    /// Enable raw mode and return a guard
    ///
    /// When the guard is dropped (goes out of scope), raw mode is disabled.
    pub fn new() -> Result<Self> {
        enable_raw_mode().context("Failed to enable raw mode")?;
        Ok(Self { _private: () })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        // Best effort to disable raw mode - if this fails, not much we can do
        let _ = disable_raw_mode();
    }
}

/// Terminal event types we care about
#[derive(Debug)]
pub enum TerminalEvent {
    /// A key was pressed
    Key(Vec<u8>),
    /// User wants to quit (Ctrl+Q)
    Quit,
    /// Terminal was resized
    Resize { cols: u16, rows: u16 },
}

/// Read a terminal event with a timeout
///
/// Returns None if no event is available within the timeout.
/// This allows us to poll for input without blocking forever.
pub fn read_event(timeout: Duration) -> Result<Option<TerminalEvent>> {
    // Check if an event is available
    if !event::poll(timeout).context("Failed to poll for events")? {
        return Ok(None);
    }

    // Read the event
    let event = event::read().context("Failed to read event")?;

    match event {
        Event::Key(key_event) => {
            // Check for our quit shortcut: Ctrl+Q
            if key_event.modifiers.contains(KeyModifiers::CONTROL)
                && key_event.code == KeyCode::Char('q')
            {
                return Ok(Some(TerminalEvent::Quit));
            }

            // Convert the key event to bytes that can be sent to the PTY
            if let Some(bytes) = key_event_to_bytes(key_event) {
                Ok(Some(TerminalEvent::Key(bytes)))
            } else {
                Ok(None) // Key we don't handle
            }
        }
        Event::Resize(cols, rows) => Ok(Some(TerminalEvent::Resize { cols, rows })),
        _ => Ok(None), // Mouse events, focus events, etc. - ignore for now
    }
}

/// Convert a crossterm KeyEvent to bytes for the PTY
///
/// The PTY expects raw bytes/escape sequences, so we need to convert
/// the structured KeyEvent into what the shell expects to receive.
fn key_event_to_bytes(key_event: KeyEvent) -> Option<Vec<u8>> {
    let KeyEvent {
        code, modifiers, ..
    } = key_event;

    // Handle Ctrl+key combinations
    if modifiers.contains(KeyModifiers::CONTROL) {
        match code {
            KeyCode::Char(c) => {
                // Ctrl+A = 0x01, Ctrl+B = 0x02, etc.
                let ctrl_char = (c.to_ascii_lowercase() as u8).wrapping_sub(b'a' - 1);
                return Some(vec![ctrl_char]);
            }
            _ => {}
        }
    }

    // Handle regular keys
    match code {
        KeyCode::Char(c) => Some(c.to_string().into_bytes()),
        KeyCode::Enter => Some(vec![b'\r']),
        KeyCode::Backspace => Some(vec![127]), // DEL character
        KeyCode::Tab => Some(vec![b'\t']),
        KeyCode::Esc => Some(vec![27]), // ESC character

        // Arrow keys send escape sequences
        KeyCode::Up => Some(b"\x1b[A".to_vec()),
        KeyCode::Down => Some(b"\x1b[B".to_vec()),
        KeyCode::Right => Some(b"\x1b[C".to_vec()),
        KeyCode::Left => Some(b"\x1b[D".to_vec()),

        // Other navigation keys
        KeyCode::Home => Some(b"\x1b[H".to_vec()),
        KeyCode::End => Some(b"\x1b[F".to_vec()),
        KeyCode::PageUp => Some(b"\x1b[5~".to_vec()),
        KeyCode::PageDown => Some(b"\x1b[6~".to_vec()),
        KeyCode::Delete => Some(b"\x1b[3~".to_vec()),
        KeyCode::Insert => Some(b"\x1b[2~".to_vec()),

        // Function keys
        KeyCode::F(1) => Some(b"\x1bOP".to_vec()),
        KeyCode::F(2) => Some(b"\x1bOQ".to_vec()),
        KeyCode::F(3) => Some(b"\x1bOR".to_vec()),
        KeyCode::F(4) => Some(b"\x1bOS".to_vec()),
        KeyCode::F(n) if n >= 5 && n <= 12 => {
            // F5-F12 have different sequences
            let seq = match n {
                5 => b"\x1b[15~".to_vec(),
                6 => b"\x1b[17~".to_vec(),
                7 => b"\x1b[18~".to_vec(),
                8 => b"\x1b[19~".to_vec(),
                9 => b"\x1b[20~".to_vec(),
                10 => b"\x1b[21~".to_vec(),
                11 => b"\x1b[23~".to_vec(),
                12 => b"\x1b[24~".to_vec(),
                _ => return None,
            };
            Some(seq)
        }

        _ => None, // Unknown key
    }
}

/// Write bytes directly to stdout
///
/// This is used to display PTY output to the user's terminal.
pub fn write_stdout(data: &[u8]) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(data).context("Failed to write to stdout")?;
    stdout.flush().context("Failed to flush stdout")?;
    Ok(())
}

/// Get current terminal size
pub fn get_size() -> Result<(u16, u16)> {
    terminal::size().context("Failed to get terminal size")
}
