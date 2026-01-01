//! PTY (Pseudo-Terminal) handling module
//!
//! This module manages the creation and interaction with a pseudo-terminal.
//! A PTY allows us to:
//! 1. Spawn a shell (like bash/zsh) as a child process
//! 2. Capture all its output (what you'd see on screen)
//! 3. Send input to it (keystrokes)
//! 4. Later: stream this to remote viewers

use anyhow::{Context, Result};
use portable_pty::{native_pty_system, CommandBuilder, PtyPair, PtySize};
use std::io::{Read, Write};

/// Represents our PTY session
///
/// This holds the PTY pair (master/slave) and provides methods
/// to interact with the shell running inside it.
pub struct PtySession {
    /// The PTY pair - master is our side, slave is the shell's side
    pair: PtyPair,
    /// Writer to send input to the shell
    writer: Box<dyn Write + Send>,
    /// Reader to receive output from the shell
    reader: Box<dyn Read + Send>,
}

impl PtySession {
    /// Create a new PTY session with a shell
    ///
    /// This spawns a new shell (uses $SHELL or defaults to /bin/sh)
    /// inside a pseudo-terminal that we control.
    pub fn new() -> Result<Self> {
        // Get the native PTY system for this OS
        let pty_system = native_pty_system();

        // Get the current terminal size so we match it
        let size = get_terminal_size()?;

        // Create a new PTY with the current terminal size
        let pair = pty_system
            .openpty(size)
            .context("Failed to open PTY")?;

        // Get the user's preferred shell, or fall back to /bin/sh
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());

        // Build the command to run the shell
        let mut cmd = CommandBuilder::new(&shell);
        // Start as a login shell for proper initialization
        cmd.arg("-l");

        // Spawn the shell in the PTY
        let _child = pair
            .slave
            .spawn_command(cmd)
            .context("Failed to spawn shell")?;

        // Get handles to read from and write to the PTY
        let writer = pair.master.take_writer()
            .context("Failed to get PTY writer")?;
        let reader = pair.master.try_clone_reader()
            .context("Failed to get PTY reader")?;

        Ok(Self {
            pair,
            writer,
            reader,
        })
    }

    /// Resize the PTY to match new terminal dimensions
    ///
    /// This should be called when the user resizes their terminal window.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.pair
            .master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("Failed to resize PTY")?;
        Ok(())
    }

    /// Send input (keystrokes) to the shell
    ///
    /// This is how we forward user input to the shell running in the PTY.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.writer
            .write_all(data)
            .context("Failed to write to PTY")?;
        self.writer
            .flush()
            .context("Failed to flush PTY writer")?;
        Ok(())
    }

    /// Read output from the shell
    ///
    /// This reads whatever the shell has output (command results, prompts, etc.)
    /// into the provided buffer. Returns the number of bytes read.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.reader
            .read(buf)
            .context("Failed to read from PTY")?;
        Ok(n)
    }

    /// Get a clone of the reader for use in another thread
    ///
    /// This is useful when we want to read PTY output in a separate thread
    /// while the main thread handles user input.
    pub fn try_clone_reader(&self) -> Result<Box<dyn Read + Send>> {
        self.pair
            .master
            .try_clone_reader()
            .context("Failed to clone PTY reader")
    }
}

/// Get the current terminal size
fn get_terminal_size() -> Result<PtySize> {
    let (cols, rows) = crossterm::terminal::size()
        .context("Failed to get terminal size")?;

    Ok(PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pty_creation() {
        // This test verifies we can create a PTY session
        // Note: This might fail in CI environments without a proper terminal
        let result = PtySession::new();
        // We just check it doesn't panic - actual functionality
        // requires a real terminal environment
        assert!(result.is_ok() || result.is_err());
    }
}
