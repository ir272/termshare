//! TermShare - Share your terminal with others in real-time
//!
//! Run `termshare` to start a terminal session that can be viewed
//! by others in their web browser.

mod pty;
mod server;
mod terminal;
mod tunnel;

use anyhow::Result;
use clap::Parser;
use std::io::Read;
use std::net::UdpSocket;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::pty::PtySession;
use crate::server::ServerState;
use crate::terminal::{read_event, write_stdout, RawModeGuard, TerminalEvent};

const DEFAULT_PORT: u16 = 3001;

/// TermShare - Share your terminal with others in real-time
#[derive(Parser, Debug)]
#[command(name = "termshare")]
#[command(version = "0.1.0")]
#[command(about = "Share your terminal with others in real-time")]
struct Args {
    /// Port to run the server on
    #[arg(short, long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Require password to view the session
    #[arg(long)]
    password: bool,

    /// Expose to local network (bind to 0.0.0.0 instead of localhost)
    #[arg(long)]
    expose: bool,

    /// Allow viewers to send input to the terminal
    #[arg(long)]
    allow_input: bool,

    /// Create a public tunnel (share over the internet with HTTPS)
    #[arg(long)]
    public: bool,
}

/// Get the local IP address for LAN sharing
fn get_local_ip() -> Option<String> {
    // Create a UDP socket and "connect" to an external IP
    // This doesn't send any data, but lets us see which local IP would be used
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let args = Args::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("termshare=info")
        .with_writer(std::io::stderr)
        .init();

    // Get password if requested
    let password = if args.password {
        println!("Enter session password: ");
        let pass = rpassword::read_password()?;
        if pass.is_empty() {
            println!("Warning: Empty password provided. Session will be unprotected.");
            None
        } else {
            Some(pass)
        }
    } else {
        None
    };

    // Create channel for viewer input
    let (viewer_input_tx, viewer_input_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);

    // Create server state with optional password and input permission
    let state = Arc::new(ServerState::new(viewer_input_tx, password.clone(), args.allow_input));
    let session_id = state.session_id.clone();

    // Warn if exposing without password
    if args.expose && password.is_none() {
        println!();
        println!("⚠️  WARNING: Exposing to network without password protection!");
        println!("   Anyone on your network can view this terminal.");
        println!("   Consider using --password for security.");
    }

    // Warn if allowing input without password
    if args.allow_input && password.is_none() {
        println!();
        println!("⚠️  WARNING: Input enabled without password protection!");
        println!("   Anyone who connects can run commands in your terminal.");
        println!("   Strongly consider using --password for security.");
    }

    // Warn if public without password
    if args.public && password.is_none() {
        println!();
        println!("⚠️  WARNING: Public sharing without password protection!");
        println!("   Anyone on the internet can view this terminal.");
        println!("   Strongly consider using --password for security.");
    }

    // Start public tunnel if requested
    let _tunnel = if args.public {
        println!();
        println!("Starting public tunnel...");
        match tunnel::start_tunnel(args.port).await {
            Ok(t) => {
                println!("Tunnel established!");
                Some(t)
            }
            Err(e) => {
                println!("Failed to start tunnel: {}", e);
                println!("Continuing with local-only access.");
                None
            }
        }
    } else {
        None
    };

    // Print startup banner
    println!();
    println!("TermShare v0.1.0 - Terminal Sharing Tool");
    println!("=========================================");
    println!();

    // Show URLs based on mode
    if let Some(ref t) = _tunnel {
        println!("🌐 Public URL: {}", t.url);
        println!("   (HTTPS secured, anyone can connect)");
        println!();
        println!("Local URL:  http://localhost:{}", args.port);
    } else if args.expose {
        println!("Local URL:   http://localhost:{}", args.port);
        if let Some(ip) = get_local_ip() {
            println!("Network URL: http://{}:{}", ip, args.port);
        }
        println!();
        println!("(Use --public to share over the internet)");
    } else {
        println!("Share URL: http://localhost:{}", args.port);
        println!();
        println!("(Use --expose for LAN, --public for internet)");
    }

    println!();
    println!("Session ID: {}", session_id);
    println!("Password protected: {}", if password.is_some() { "Yes" } else { "No" });
    println!("Viewer input: {}", if args.allow_input { "Enabled" } else { "View only" });
    println!();
    println!("Starting shell session...");
    println!("Press Ctrl+Q to exit");
    println!();

    // Start web server in background
    // Enable expose if public tunnel is active (need to bind to 0.0.0.0)
    let server_state = state.clone();
    let port = args.port;
    let expose = args.expose || args.public;
    tokio::spawn(async move {
        if let Err(e) = server::start_server(server_state, port, expose).await {
            tracing::error!("Server error: {}", e);
        }
    });

    // Small delay to let server start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run the main terminal session
    run_session(state, viewer_input_rx).await?;

    println!();
    println!("Session ended. Goodbye!");
    Ok(())
}

/// Run the main terminal session with network sharing
async fn run_session(
    state: Arc<ServerState>,
    mut viewer_input_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    // Create the PTY session (spawns a shell)
    let mut pty = PtySession::new()?;

    // Enable raw mode
    let _raw_guard = RawModeGuard::new()?;

    // Create channel for PTY output
    let (pty_output_tx, pty_output_rx) = std::sync::mpsc::channel::<Vec<u8>>();

    // Clone PTY reader for the reader thread
    let mut pty_reader = pty.try_clone_reader()?;

    // Spawn thread to read PTY output
    let reader_handle = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if pty_output_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("PTY read error: {}", e);
                    break;
                }
            }
        }
    });

    // Main event loop
    loop {
        // Check for PTY output (non-blocking)
        while let Ok(output) = pty_output_rx.try_recv() {
            // Display locally
            write_stdout(&output)?;

            // Broadcast to viewers (and store in buffer)
            state.broadcast_output(&output).await;
        }

        // Check for viewer input (non-blocking)
        while let Ok(input) = viewer_input_rx.try_recv() {
            // Send viewer input to PTY
            pty.write(&input)?;
        }

        // Check for local keyboard input
        if let Some(event) = read_event(Duration::from_millis(10))? {
            match event {
                TerminalEvent::Key(bytes) => {
                    pty.write(&bytes)?;
                }
                TerminalEvent::Quit => {
                    break;
                }
                TerminalEvent::Resize { cols, rows } => {
                    pty.resize(cols, rows)?;
                    // Broadcast resize to viewers
                    state.broadcast_resize(cols, rows).await;
                }
            }
        }

        // Check if PTY reader finished (shell exited)
        if reader_handle.is_finished() {
            break;
        }

        // Small yield to prevent busy loop
        tokio::task::yield_now().await;
    }

    let _ = reader_handle.join();
    Ok(())
}
