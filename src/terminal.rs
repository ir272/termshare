use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use std::io::{self, Write};
use std::time::Duration;

/// Guard that restores normal terminal state when dropped
pub struct RawModeGuard {
    _private: (),
}

impl RawModeGuard {
    pub fn new() -> Result<Self> {
        enable_raw_mode().context("Failed to enable raw mode")?;
        Ok(Self { _private: () })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

#[derive(Debug)]
pub enum TerminalEvent {
    Key(Vec<u8>),
    Quit,
    Resize { cols: u16, rows: u16 },
}

/// Read a terminal event with timeout. Returns None if no event available.
pub fn read_event(timeout: Duration) -> Result<Option<TerminalEvent>> {
    if !event::poll(timeout).context("Failed to poll for events")? {
        return Ok(None);
    }

    let event = event::read().context("Failed to read event")?;

    match event {
        Event::Key(key_event) => {
            // Quit shortcut: Ctrl+Q
            if key_event.modifiers.contains(KeyModifiers::CONTROL)
                && key_event.code == KeyCode::Char('q')
            {
                return Ok(Some(TerminalEvent::Quit));
            }

            if let Some(bytes) = key_event_to_bytes(key_event) {
                Ok(Some(TerminalEvent::Key(bytes)))
            } else {
                Ok(None)
            }
        }
        Event::Resize(cols, rows) => Ok(Some(TerminalEvent::Resize { cols, rows })),
        _ => Ok(None),
    }
}

/// Convert KeyEvent to bytes/escape sequences for the PTY
fn key_event_to_bytes(key_event: KeyEvent) -> Option<Vec<u8>> {
    let KeyEvent {
        code, modifiers, ..
    } = key_event;

    // Ctrl+key: Ctrl+A = 0x01, Ctrl+B = 0x02, etc.
    if modifiers.contains(KeyModifiers::CONTROL) {
        if let KeyCode::Char(c) = code {
            let ctrl_char = (c.to_ascii_lowercase() as u8).wrapping_sub(b'a' - 1);
            return Some(vec![ctrl_char]);
        }
    }

    match code {
        KeyCode::Char(c) => Some(c.to_string().into_bytes()),
        KeyCode::Enter => Some(vec![b'\r']),
        KeyCode::Backspace => Some(vec![127]),
        KeyCode::Tab => Some(vec![b'\t']),
        KeyCode::Esc => Some(vec![27]),

        // Arrow keys
        KeyCode::Up => Some(b"\x1b[A".to_vec()),
        KeyCode::Down => Some(b"\x1b[B".to_vec()),
        KeyCode::Right => Some(b"\x1b[C".to_vec()),
        KeyCode::Left => Some(b"\x1b[D".to_vec()),

        // Navigation
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

        _ => None,
    }
}

pub fn write_stdout(data: &[u8]) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(data).context("Failed to write to stdout")?;
    stdout.flush().context("Failed to flush stdout")?;
    Ok(())
}
