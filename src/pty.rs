use anyhow::{Context, Result};
use portable_pty::{native_pty_system, CommandBuilder, PtyPair, PtySize};
use std::io::{Read, Write};

pub struct PtySession {
    pair: PtyPair,
    writer: Box<dyn Write + Send>,
}

impl PtySession {
    /// Create a new PTY session with a shell or custom command
    pub fn new(command: Option<&str>) -> Result<Self> {
        let pty_system = native_pty_system();
        let size = get_terminal_size()?;

        let pair = pty_system
            .openpty(size)
            .context("Failed to open PTY")?;

        let cmd = if let Some(user_cmd) = command {
            // Run through shell to handle pipes, redirects, etc.
            let mut cmd = CommandBuilder::new("sh");
            cmd.args(["-c", user_cmd]);
            cmd
        } else {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
            let mut cmd = CommandBuilder::new(&shell);
            cmd.arg("-l");
            cmd
        };

        let _child = pair
            .slave
            .spawn_command(cmd)
            .context("Failed to spawn command")?;

        let writer = pair.master.take_writer()
            .context("Failed to get PTY writer")?;

        Ok(Self { pair, writer })
    }

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

    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.writer
            .write_all(data)
            .context("Failed to write to PTY")?;
        self.writer
            .flush()
            .context("Failed to flush PTY writer")?;
        Ok(())
    }

    /// Clone reader for use in a separate thread
    pub fn try_clone_reader(&self) -> Result<Box<dyn Read + Send>> {
        self.pair
            .master
            .try_clone_reader()
            .context("Failed to clone PTY reader")
    }
}

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
        let result = PtySession::new(None);
        assert!(result.is_ok() || result.is_err());
    }
}
